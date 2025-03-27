from __future__ import annotations

import os
import sys
from asyncio import CancelledError
from typing import Any
from typing import BinaryIO
from typing import Coroutine
from typing import List
from typing import Tuple

import lldb

import pwndbg
from pwndbg.dbg.lldb import YieldContinue
from pwndbg.dbg.lldb import YieldSingleStep
from pwndbg.dbg.lldb.repl.io import IODriver
from pwndbg.dbg.lldb.repl.io import IODriverPlainText


class EventHandler:
    """
    The event types that make sense for us to track in the process driver aren't
    the same as the ones in the rest of Pwndbg, so we just expose the native
    events in process driver, and let the rest of the REPL deal with any
    complexities that might arise from the translation.

    This is mostly intended to keep the complexity of generating the START and
    NEW_THREAD events correctly out of the process driver.
    """

    def created(self):
        """
        This function is called when a process is created or attached to.
        """
        pass

    def suspended(self):
        """
        This function is called when the execution of a process is suspended.
        """
        pass

    def resumed(self):
        """
        This function is called when the execution of a process is resumed.
        """
        pass

    def exited(self):
        """
        This function is called when a process terminates or is detached from.
        """
        pass

    def modules_loaded(self):
        """
        This function is called when a new modules have been loaded.
        """
        pass


class ProcessDriver:
    """
    Drives the execution of a process, responding to its events and handling its
    I/O, and exposes a simple synchronous interface to the REPL interface.
    """

    io: IODriver
    process: lldb.SBProcess
    listener: lldb.SBListener
    debug: bool
    eh: EventHandler
    cancellation_requested: bool

    def __init__(self, event_handler: EventHandler, debug=False):
        self.io = None
        self.process = None
        self.listener = None
        self.debug = debug
        self.eh = event_handler
        self.cancellation_requested = False

    def has_process(self) -> bool:
        """
        Whether there's an active process in this driver.
        """
        return self.process is not None and self.process.GetState() != lldb.eStateConnected

    def has_connection(self) -> bool:
        """
        Whether this driver's connected to a target. All drivers that have an
        active process also must necessarily be connected.
        """
        return self.process is not None

    def cancel(self) -> None:
        """
        Request that a currently ongoing operation be cancelled.
        """
        self.cancellation_requested = True

    def _should_cancel(self) -> bool:
        """
        Checks whether a cancellation has been requested, and clears cancellation state.
        """
        should = self.cancellation_requested
        self._clear_cancel()

        return should

    def _clear_cancel(self) -> None:
        """
        Clears cancellation state.
        """
        self.cancellation_requested = False

    def interrupt(self) -> None:
        """
        Interrupts the currently running process.
        """
        assert self.has_process(), "called interrupt() on a driver with no process"
        self.process.SendAsyncInterrupt()

    def _run_until_next_stop(
        self,
        with_io: bool = True,
        timeout: int = 1,
        first_timeout: int = 1,
        only_if_started: bool = False,
        fire_events: bool = True,
    ) -> Tuple[bool, lldb.SBEvent | None]:
        """
        Runs the event loop of the process until the next stop event is hit, with
        a configurable timeouts for the first and subsequent timeouts.

        Optionally runs the I/O system alongside the event loop.

        If `only_if_started` is passed, this method will stop after the first
        timeout if it can't observe a state change to a running state, and I/O
        will only start running after the start event is observed.
        """

        # If `only_if_started` is set, we defer the starting of the I/O driver
        # to the moment the start event is observed. Otherwise, we just start it
        # immediately.
        io_started = False
        if with_io and not only_if_started:
            self.io.start(process=self.process)
            io_started = True

        # Pick the first timeout value.
        timeout_time = first_timeout

        # If `only_if_started` is not set, assume the process must have been
        # started by a previous action and is running.
        running = not only_if_started

        last: lldb.SBEvent | None = None
        expected: bool = False
        while True:
            event = lldb.SBEvent()
            if not self.listener.WaitForEvent(timeout_time, event):
                if self.debug:
                    print(f"[-] ProcessDriver: Timed out after {timeout_time}s")
                timeout_time = timeout

                # If the process isn't running, we should stop.
                if not running:
                    if self.debug:
                        print(
                            "[-] ProcessDriver: Waited too long for process to start running, giving up"
                        )
                    break

                continue
            last = event

            if self.debug:
                descr = lldb.SBStream()
                if event.GetDescription(descr):
                    print(f"[-] ProcessDriver: {descr.GetData()}")
                else:
                    print(f"[!] ProcessDriver: No description for {event}")

            if lldb.SBTarget.EventIsTargetEvent(event):
                if event.GetType() == lldb.SBTarget.eBroadcastBitModulesLoaded:
                    # Notify the event handler that new modules got loaded in.
                    if fire_events:
                        self.eh.modules_loaded()

            elif lldb.SBProcess.EventIsProcessEvent(event):
                if (
                    event.GetType() == lldb.SBProcess.eBroadcastBitSTDOUT
                    or event.GetType() == lldb.SBProcess.eBroadcastBitSTDERR
                ):
                    # Notify the I/O driver that the process might have something
                    # new for it to consume.
                    self.io.on_output_event()
                elif event.GetType() == lldb.SBProcess.eBroadcastBitStateChanged:
                    # The state of the process has changed.
                    new_state = lldb.SBProcess.GetStateFromEvent(event)
                    was_resumed = lldb.SBProcess.GetRestartedFromEvent(event)

                    if new_state == lldb.eStateStopped and not was_resumed:
                        # The process has stopped, so we're done processing events
                        # for the time being. Trigger the stopped event and return.
                        if fire_events:
                            self.eh.suspended()
                        expected = True
                        break

                    if new_state == lldb.eStateRunning or new_state == lldb.eStateStepping:
                        running = True
                        # Start the I/O driver here if its start got deferred
                        # because of `only_if_started` being set.
                        if only_if_started and with_io:
                            self.io.start(process=self.process)
                            io_started = True

                    if (
                        new_state == lldb.eStateExited
                        or new_state == lldb.eStateCrashed
                        or new_state == lldb.eStateDetached
                    ):
                        # Nothing else for us to do here. Clear our internal
                        # references to the process, fire the exit event, and leave.
                        if self.debug:
                            print(f"[-] ProcessDriver: Process exited with state {new_state}")
                        self.process = None
                        self.listener = None

                        if fire_events:
                            self.eh.exited()
                        break

        if io_started:
            self.io.stop()

        return expected, last

    def cont(self) -> None:
        """
        Continues execution of the process this object is driving, and returns
        whenever the process stops.
        """
        assert self.has_process(), "called cont() on a driver with no process"

        self.eh.resumed()
        self.process.Continue()
        self._run_until_next_stop()

    def run_lldb_command(self, command: str, target: BinaryIO) -> None:
        """
        Runs the given LLDB command and ataches I/O if necessary.
        """
        assert self.has_process(), "called run_lldb_command() on a driver with no process"

        ret = lldb.SBCommandReturnObject()
        self.process.GetTarget().GetDebugger().GetCommandInterpreter().HandleCommand(command, ret)

        if ret.IsValid():
            # LLDB can give us strings that may fail to encode.
            out = ret.GetOutput().strip()
            if len(out) > 0:
                target.write(out.encode(sys.stdout.encoding, errors="backslashreplace"))
                target.write(b"\n")
            out = ret.GetError().strip()
            if len(out) > 0:
                target.write(out.encode(sys.stdout.encoding, errors="backslashreplace"))
                target.write(b"\n")

            if self.debug:
                print(f"[-] ProcessDriver: LLDB Command Status: {ret.GetStatus():#x}")

            # Only call _run_until_next_stop() if the command started the process.
            start_expected = True
            s = ret.GetStatus()
            if s == lldb.eReturnStatusFailed:
                start_expected = False
            if s == lldb.eReturnStatusQuit:
                start_expected = False
            if s == lldb.eReturnStatusSuccessFinishResult:
                start_expected = False
            if s == lldb.eReturnStatusSuccessFinishNoResult:
                start_expected = False

            # It's important to note that we can't trigger the resumed event
            # now because the process might've already started, and LLDB
            # will fail to do most of the operations that we need while the
            # process is running. Ideally, we'd have a way to trigger the
            # event right before the process is resumed, but as far as I know,
            # there is no way to do that.
            #
            # TODO/FIXME: Find a way to trigger the continued event before the process is resumed in LLDB

            if not start_expected:
                # Even if the current process has not been resumed, LLDB might
                # have posted process events for us to handle. Do so now, but
                # stop right away if there is nothing for us in the listener.
                #
                # This lets us handle things like `detach`, which would otherwise
                # pass as a command that does not change process state at all.
                self._run_until_next_stop(first_timeout=0, only_if_started=True)
            else:
                self._run_until_next_stop()

    def run_coroutine(self, coroutine: Coroutine[Any, Any, None]) -> bool:
        """
        Runs the given coroutine and allows it to control the execution of the
        process in this driver. Returns `True` if the coroutine ran to completion,
        and `False` if it was cancelled.
        """
        assert self.has_process(), "called run_coroutine() on a driver with no process"
        exception: Exception | None = None
        self._clear_cancel()
        while True:
            if self._should_cancel():
                # We were requested to cancel the execution controller.
                exception = CancelledError()

            try:
                if exception is None:
                    step = coroutine.send(None)
                else:
                    step = coroutine.throw(exception)
                    # The coroutine has caught the exception. Continue running
                    # it as if nothing happened.
                    exception = None
            except StopIteration:
                # We got to the end of the coroutine. We're done.
                break
            except CancelledError:
                # We requested that the coroutine be cancelled, and it didn't
                # override our decision. We're done.
                break

            if isinstance(step, YieldSingleStep):
                # Pick the currently selected thread and step it forward by one
                # instruction.
                #
                # LLDB lets us step any thread that we choose, so, maybe we
                # should consider letting the caller pick which thread they want
                # the step to happen in?
                thread = self.process.GetSelectedThread()
                assert thread is not None, "Tried to single step, but no thread is selected?"

                e = lldb.SBError()
                thread.StepInstruction(False, e)
                if not e.success:
                    # The step failed. Raise an error in the coroutine and give
                    # it a chance to recover gracefully before we propagate it
                    # up to the caller.
                    exception = pwndbg.dbg_mod.Error(
                        f"Could not perform single step: {e.description}"
                    )
                    continue

                healthy, event = self._run_until_next_stop()
                if not healthy:
                    # The process exited. Cancel the execution controller.
                    exception = CancelledError()
                    continue

            elif isinstance(step, YieldContinue):
                # Continue the process and wait for the next stop-like event.
                self.process.Continue()
                healthy, event = self._run_until_next_stop()
                if not healthy:
                    # The process exited, Cancel the execution controller.
                    exception = CancelledError()
                    continue

                # Check whether this stop event is the one we expect.
                stop: lldb.SBBreakpoint | lldb.SBWatchpoint = step.target.inner

                if lldb.SBProcess.GetStateFromEvent(event) == lldb.eStateStopped:
                    matches = 0
                    for thread in lldb.SBProcess.GetProcessFromEvent(event).threads:
                        # We only check the stop reason, as the other methods
                        # for querying thread state (`IsStopped`, `IsSuspended`)
                        # are unreliable[1][2], and so we just assume that
                        # after a stop event, all the threads are stopped[3].
                        #
                        # [1]: https://github.com/llvm/llvm-project/issues/16196
                        # [2]: https://discourse.llvm.org/t/bug-28455-new-thread-state-not-in-sync-with-process-state/41699
                        # [3]: https://discourse.llvm.org/t/sbthread-isstopped-always-returns-false-on-linux/36944/5

                        bpwp_id = None
                        if thread.GetStopReason() == lldb.eStopReasonBreakpoint and isinstance(
                            stop, lldb.SBBreakpoint
                        ):
                            bpwp_id = thread.GetStopReasonDataAtIndex(0)
                        elif thread.GetStopReason() == lldb.eStopReasonWatchpoint and isinstance(
                            stop, lldb.SBWatchpoint
                        ):
                            bpwp_id = thread.GetStopReasonDataAtIndex(0)

                        if bpwp_id is not None and stop.GetID() == bpwp_id:
                            matches += 1

                    if matches > 0:
                        # At least one of the threads got stopped by our target.
                        # Return control back to the coroutine and await further
                        # instruction.
                        pass
                    else:
                        # Something else that we weren't expecting caused the
                        # process to stop. Request that the coroutine be
                        # cancelled.
                        exception = CancelledError()
                else:
                    # The process might've crashed, been terminated, exited, or
                    # we might've lost connection to it for some other reason.
                    # Regardless, we should cancel the coroutine.
                    exception = CancelledError()

        # Let the caller distinguish between a coroutine that's been run to
        # completion and one that got cancelled.
        return not isinstance(exception, CancelledError)

    def launch(
        self, target: lldb.SBTarget, io: IODriver, env: List[str], args: List[str], working_dir: str
    ) -> lldb.SBError:
        """
        Launches the process and handles startup events. Always stops on first
        opportunity, and returns immediately after the process has stopped.

        Fires the created() event.
        """
        assert not self.has_process(), "called launch() on a driver with a live process"

        error = lldb.SBError()

        # Do the launch, proper. We always stop the target, and let the upper
        # layers deal with the user wanting the program to not stop at entry by
        # calling `cont()`.
        if self.has_connection():
            # This is a remote launch.
            #
            # We ignore the IODriver we were given, and use the plain text
            # driver, as we can't guarantee that anything else would work.
            io = IODriverPlainText()
            stdin, stdout, stderr = io.stdio()
            self.process.RemoteLaunch(
                args,
                env,
                stdin,
                stdout,
                stderr,
                None,
                lldb.eLaunchFlagStopAtEntry,
                True,
                error,
            )
        else:
            # This is a local launch.
            self.listener = lldb.SBListener("pwndbg.dbg.lldb.repl.proc.ProcessDriver")
            assert self.listener.IsValid()

            # We are interested in handling certain target events synchronously, so
            # set them up here, before LLDB has had any chance to do anything to the
            # process.
            self.listener.StartListeningForEventClass(
                target.GetDebugger(),
                lldb.SBTarget.GetBroadcasterClassName(),
                lldb.SBTarget.eBroadcastBitModulesLoaded,
            )
            stdin, stdout, stderr = io.stdio()
            self.process = target.Launch(
                self.listener,
                args,
                env,
                stdin,
                stdout,
                stderr,
                os.getcwd(),
                lldb.eLaunchFlagStopAtEntry,
                True,
                error,
            )

            if not error.success:
                # Undo any initialization Launch() might've done.
                self.process = None
                self.listener = None

        if not error.success:
            return error

        assert self.listener.IsValid()
        assert self.process.IsValid()

        self.io = io
        self._run_until_next_stop(fire_events=False)
        self.eh.created()

        return error

    def attach(self, target: lldb.SBTarget, io: IODriver, info: lldb.SBAttachInfo) -> lldb.SBError:
        """
        Attach to a process and handles startup events. Always stops on first
        opportunity, and returns immediately after the process has stopped.

        Fires the created() event.
        """
        stdin, stdout, stderr = io.stdio()
        error = lldb.SBError()
        self.listener = lldb.SBListener("pwndbg.dbg.lldb.repl.proc.ProcessDriver")
        assert self.listener.IsValid()

        # We are interested in handling certain target events synchronously, so
        # set them up here, before LLDB has had any chance to do anything to the
        # process.
        self.listener.StartListeningForEventClass(
            target.GetDebugger(),
            lldb.SBTarget.GetBroadcasterClassName(),
            lldb.SBTarget.eBroadcastBitModulesLoaded,
        )

        # Do the launch, proper. We always stop the target, and let the upper
        # layers deal with the user wanting the program to not stop at entry by
        # calling `cont()`.
        info.SetListener(self.listener)
        self.process = target.Attach(
            info,
            error,
        )

        if not error.success:
            # Undo any initialization Launch() might've done.
            self.process = None
            self.listener = None
            return error

        assert self.listener.IsValid()
        assert self.process.IsValid()

        self.io = io
        self._run_until_next_stop(fire_events=False)
        self.eh.created()

        return error

    def connect(self, target: lldb.SBTarget, io: IODriver, url: str, plugin: str) -> lldb.SBError:
        """
        Connects to a remote proces with the given URL using the plugin with the
        given name. This might cause the process to launch in some implementations,
        or it might require a call to `launch()`, in implementations that
        require a further call to `SBProcess::RemoteLaunch()`.

        Fires the created() event if a process is automatically attached to
        or launched when a connection succeeds.
        """
        assert not self.has_connection(), "called connect() on a driver with an active connection"
        stdin, stdout, stderr = io.stdio()
        error = lldb.SBError()
        self.listener = lldb.SBListener("pwndbg.dbg.lldb.repl.proc.ProcessDriver")
        assert self.listener.IsValid()

        # See `launch()`.
        self.listener.StartListeningForEventClass(
            target.GetDebugger(),
            lldb.SBTarget.GetBroadcasterClassName(),
            lldb.SBTarget.eBroadcastBitModulesLoaded,
        )

        # Connect to the given remote URL using the given remote process plugin.
        self.process = target.ConnectRemote(self.listener, url, plugin, error)

        if not error.success:
            # Undo any initialization ConnectRemote might've done.
            self.process = None
            self.listener = None
            return error

        assert self.listener.IsValid()
        assert self.process.IsValid()

        self.io = io

        # Unlike in `launch()`, it's not guaranteed that the process is actually
        # alive, as it might be in the Connected state, which indicates that
        # the connection was successful, but that we still need to launch it
        # manually in the remote target.
        while True:
            healthy, event = self._run_until_next_stop(
                with_io=False, fire_events=False, only_if_started=True
            )
            if healthy:
                # The process has startarted. We can fire off the created event
                # just fine.
                self.eh.created()
                break

            if (
                event is not None
                and lldb.SBProcess.GetStateFromEvent(event) == lldb.eStateConnected
            ):
                # This indicates that on this implementation, connecting isn't
                # enough to have the process launch or attach, and that we have
                # to do that manually.
                break

        return error
