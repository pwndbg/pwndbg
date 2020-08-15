### Contributing

Contributions to Pwndbg are always welcome! If you want to get more familiar with project idea/structure/whatever - [here are some developer notes](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md). If something is not clear, feel free to ask in a github issue!

If you want to help, fork the project, hack your changes and create a pull request.

If this is something big/new feature or a bug, consider creating an issue first.


Some guides:
* [Fork a project](https://help.github.com/articles/fork-a-repo/)
* [Pull requests](https://help.github.com/articles/about-pull-requests/)

### Versioning and releases

* There are three branches: `stable`, `beta` and `dev`
* Each developer works on his own fork
* Only bug-fixes will be merged into either `stable` or `beta`
* Every release, merges are cascaded `stable -> beta -> dev`
* After merging, a new minor-point-release (`1.X`) is created for `stable`
* Releases occur on predetermined schedule
* Bugs _are not fixed_ on releases older than the current `stable` (i.e. `0.9` is never fixed)
* Mid-cycle releases get a patch version bump (`1.1.X`) when bugs affecting `stable` or `beta` are found
* Pull requests which fix bugs target the oldest branch they affect (e.g. `stable`).
* There might be occassional cherry-picks if something is fixed in a later branch and we don't notice/forget that it should really target an earlier branch.
* Documentation fixes, CI fixes, CHANGELOG/README fixes and other tiny fixes does not trigger a new point release.

### Contact

If you want to talk with other contributors and pwndbg users 
join us at our irc channel: #pwndbg at freenode.
