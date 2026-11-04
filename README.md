# CTODCFuzzer

CTODCFuzzer is a **Common Target-Oriented Evaluation-based Directed Collaborative Fuzzing** Framework. It enables multiple directed fuzzers, including AFLGo, WindRanger, and DAFL, to collaboratefor improved target reachability and vulnerability reproduction.

## Installing

### Required system packages
- `docker`

### Build docker image
First build baseline fuzzers and benchmarks.

```
./docker/build.sh
```

Then, build the Docker image containing `CTODCFuzzer` and the required fuzzers and benchmarks::

```
./build.sh
```

The Docker image name and tag can be configured in the corresponding `build.sh` scripts.

If necessary, adjust`_UID` and `GID` in build.sh to avoid permission issues with Docker-mounted volumes.

### Increase inotify limits

Increase the inotify limits on the host system:

```sh
sysctl -w fs.inotify.max_user_instances=8192
sysctl -w fs.inotify.max_user_watches=524288
```

To make these settings persistent across reboots, add the following lines to `/etc/sysctl.conf`.

```
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=524288
```

## Running
### Launching a docker container

Launch the Docker container using:
```sh
docker run --rm --privileged -it ctodcfuzzer /bin/bash
```

By default, files generated inside the container are not preserved after the container is removed.

To preserve fuzzing results, mount a host directory:

```sh
docker run --rm --privileged -v $PWD:/work/ctodcfuzzer -w /work/ctodcfuzzer -it ctodcfuzzer /bin/bash
```

This command mounts the current directory (`$PWD`) to `/work/ctodcfuzzer` inside the container and sets it as the working directory.

Ensure that the fuzzing output directory is located under `/work/ctodcfuzzer` to preserve the results on the host.

### Initialization

After entering the docker container, run the following commands; it will setup necessary parameters for fuzzing and create the cgroups.

```sh
sudo /init.sh
```

#### Cgroups V2
For a system that is using cgroup v2, a manual downgrade to v1 is necessary. This can be done by adding `systemd.unified_cgroup_hierarchy=0` to the kernel command line (e.g., via /etc/default/grub).

### Fuzzing ###
`CTODCFuzzer`  supports collaborative fuzzing with AFLGo, WindRanger, and DAFL..
For the complete list of command-line arguments, refer to [cli.py](./ctodcfuzzer/cli.py) .

#### Example ####

The following command runs  `CTODCFuzzer` on the target vulnerability  `swftophp-2016-9829` using `AFLGo`, `WindRanger`, `DAFL`:

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
