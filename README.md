# CTODCFuzzer

## Installing

### Required system packages
- `docker`

### Build docker image
To build the Docker image, follow these steps:

First build baseline fuzzers and benchmarks.

```
./docker/build.sh
```

Then, build the all-in-one docker including `ctodcfuzzer` and all the fuzzers/benchmarks.

```
./build.sh
```

You can tune the image name/tag in these `build.sh`.

You might need to tune `_UID` and `GID` (they are hard-coded to `2000` when building the pre-built image) in `build.sh` to bypass docker volume permission issue if you don't want to use root user.

#### Build Note/Warning

The build script parallels the compilation process a lot by making the jobs runs in the background (by inserting `&` at the end of shell commands). It will takes a lot of CPU and RAM (especially during linking). Please remove `&` in build scripts (`build.sh` or `build_all.sh` under `docker/benchmark`) when you are building under less performant machines.

### Increase inotify limits
```sh
sysctl -w fs.inotify.max_user_instances=8192
sysctl -w fs.inotify.max_user_watches=524288
```
To make it persistent between reboot; add the following lines to `/etc/sysctl.conf` on the host.
```
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=524288
```

## Running
### Launching a docker container
```sh
docker run --rm --privileged -it ctodcfuzzer /bin/bash
```
Note that, the result is not preserved. To preserve the fuzzing output, we need
to mount a docker volume.

```sh
docker run --rm --privileged -v $PWD:/work/ctodcfuzzer -w /work/ctodcfuzzer -it ctodcfuzzer /bin/bash
```
This command mount (by `-v`) your current directory (`$PWD`) to `/work/ctodcfueer` in the container and change the working directory to `/work/ctodcfueer` (by `-w`).

Afterward, make sure the fuzzing output directory is under `/work/ctodcfuzzer` and it will be preserved under your `$PWD`.

### Note for expeirments
It is supposed to run **only one** ctodcfuzzer instance at the same time in a single container for the current implementation.

All ctodcfuzzer instances in the same container share a single cgroup for the current implementaion.

Generating different cgroup subgroups for differnet instances is on the roadmap.

### Init
After entering the docker container, run the following commands; it will setup necessary parameters for fuzzing and create the cgroups.
```sh
sudo /init.sh
```

#### Cgroups V2
For a system that is using cgroup v2, a manual downgrade to v1 is necessary. This can be done by adding `systemd.unified_cgroup_hierarchy=0` to the kernel command line (e.g., via /etc/default/grub).

Thanks for the anonymous reviewers for suggestion.

### Fuzzing ###
All the evaluation is run by `ctodcfuzzer` framework.
Please refer to [cli.py](./ctodcfuzzer/cli.py) for all possible arguments.

#### ctodcfuzzer ####

For example, we want to fuzz `swftophp-2016-9829` (by `-t`) using 3 fuzzers by `-f`: `AFLGo`, `WindRanger`, `DAFL`. `-T` for the timeout.

The fuzzing result reside in `output` (by specifying `-o`).

```sh
ctodcfuzzer -o output -f aflgo dafl windranger --focus 300 --weight 20 --sync_top_k 10 -T 86400 -t swftophp-2016-9829
```

The command-line options are described below:
- `-o`: Directory for storing fuzzing results.
- `-f`: Directed fuzzers participating in collaborative fuzzing.
- `--focus`: Execution time allocated to each selected fuzzer (in seconds).(default: 300)
- `--weight`: Ealuation weight used to update the Thompson sampling distributions.(default: 20)
- `--sync_top_k`: Number of top-ranked seeds selected per evaluation metric for seed synchronization.(default: 10)
- `-T`: Total fuzzing timeout (in seconds).(default: 86400)
- `-t`: Target vulnerability.
