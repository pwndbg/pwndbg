# Stacked PRs

A "stacked PR" is a Pull Request that includes the changes of another PR which has not yet been merged. This most often comes up when you have made a PR which is taking some time to get reviewed. You want to add some more stuff that is based on that work, and would like to work on it now due to time/motivation, but don't want to push it to the PR that hasn't yet been reviewed since that is likely to make the review process more cumbersome and take more time.

Unfortunately, Github doesn't really have a nice way with dealing with stacked PRs. I will recommend a workflow here, but if you have a better way to do it feel free to update these docs :P.

Imagine your first (unreviewed) PR is on branch `my-cool-branch`. First make a new branch that is based off of that one:
```{.bash .copy}
git switch my-cool-branch
git switch --create my-even-cooler-branch
```
After you can make your new changes and push them:
```{.bash .copy}
git add .
git commit -m "a meaningful commit message"
git push
```
Open the new PR against the `pwndbg/pwndbg` repository and the `dev` branch. You might be tempted to open it against your `my-cool-branch` branch, but then it won't be seen by the pwndbg maintainers in the Pull Requests tab. If you plan to stack a significant amount of PRs, it may be smarter to in fact open it against your own branch and fork, to not clutter the pwndbg Pull Requests; you can always open another one on the main `pwndbg/pwndbg` repository when you're ready. Up to you!

The stacked PR you create should be a "Draft" PR, and it should contain the words "Requires #<PR-number-for-the-my-cool-branch-PR\>". Unfortunately, the Github "Files changed" diff will show all the changes from `my-cool-branch` as well, it is what it is.

After the `my-cool-branch` PR is reviewed and merged, it will create a squash commit on the `dev` branch. Now you should rebase your `my-even-cooler-branch` branch. First, you should take note of what the top commit of `my-cool-branch` is.
```{.bash .copy}
git switch my-cool-branch
git show
# You will get something like this:
# =================================
# commit cefc12099f9a402fcc5574bfa8b334bd55c92cce
# Author: yourname <youremail@users.noreply.github.com>
# Date:   datetime
#  
#     some really cool commit message
#  
# diff --git a/pwndbg/libc/__init__.py b/pwndbg/libc/__init__.p
# =================================
# Remember the commit message!
```
Now, rebase your `my-even-cooler-branch` onto dev, and make sure to drop all the commits that are from `my-cool-branch` (all those changes will come from the squashed commit). If you're scared about messing something up, you can first make a backup branch:
```{.bash .copy}
git switch my-even-cooler-branch
git switch --create my-even-cooler-branch-backup
```
Make sure your dev branch is up to date. You can either do that by clicking "Sync fork" in the Github UI of your fork and then pulling the changes locally, or by maintaining a branch that tracks pwndbg/dev (I recommend this method, I call this branch `updev`). In any case, you can now do the rebase:
```{.bash .copy}
git switch my-even-cooler-branch
git rebase dev --interactive
# You will get a file like this:
pick 46641c999 # infrastructure
pick 3b139c7a4 # delete old
pick a8270e2dc # change signature of elf section functions
pick b69d28168 # stabilize api
pick 778709aa3 # change all callees to use the new api
pick b83219cb5 # fix bug in addr_region_start
pick e58f56766 # clean up API and document it
pick 9aecf07bd # implement some apis
pick bdbcb41e5 # some factors and notes
pick cefc12099 # some really cool commit message
pick ddd78b8c4 # progress!
pick e4a55f191 # fixes from the gdb stack pr
pick fd208cc96 # wild libc detection
pick 72f454086 # sensible setup
pick 6ec50c089 # more precise and faster check
pick aa8150cfb # fix glibc version check
pick 6470550e7 # fix api users
pick 3112a9d41 # fix version usages
pick f82403327 # fix lookup logi
```
You want to drop all of the commits from your old branch, by marking them with `drop` instead of `pick`, ending with the commit you noted above. So you should modify the file to look something like this:
```{.bash .copy}
drop 46641c999 # infrastructure
drop 3b139c7a4 # delete old
drop a8270e2dc # change signature of elf section functions
drop b69d28168 # stabilize api
drop 778709aa3 # change all callees to use the new api
drop b83219cb5 # fix bug in addr_region_start
drop e58f56766 # clean up API and document it
drop 9aecf07bd # implement some apis
drop bdbcb41e5 # some factors and notes
drop cefc12099 # some really cool commit message
pick ddd78b8c4 # progress!
pick e4a55f191 # fixes from the gdb stack pr
pick fd208cc96 # wild libc detection
pick 72f454086 # sensible setup
pick 6ec50c089 # more precise and faster check
pick aa8150cfb # fix glibc version check
pick 6470550e7 # fix api users
pick 3112a9d41 # fix version usages
pick f82403327 # fix lookup logi
```
Hopefully you got a "Successfully rebased and updated refs/heads/my-even-cooler-branch." And you will now need to force push the changes.
```{.bash .copy}
git push --force
```
And finally, you remove the Draft status from your PR in the Github UI (you should leave the "Requires" line in the PR description). Thats all. Yeah, it's a bit of a dance :p.

!!! note
    Naturally, while `my-cool-branch` is being reviewed you will be pushing changes to it. Don't forget to keep your `my-even-cooler-branch` branch up to date by rebasing often:
    ```{.bash .copy}
    git switch my-even-cooler-branch
    git rebase my-cool-branch
    ```
