# Running ccf-agent as a Daemon/Service

By default when you run the ccf-agent agent it will run as a one off process and
exit when it is done.

You can also run the ccf-agent agent can run as a daemon or a service (same thing
for this document) on Linux through systemd, Mac through launchd or Windows
through Windows services. It is recommended to run the ccf-agent agent as a service
for tasks such as:
* Checking machine specific status such as SSH root login being enabled, etc.
  The specifics can be configured as per the documentation
  [here](configuration.md).
* Running specific checks related to internal network security.
* Running as a server to do checks against external machines or APIs, etc.
* Running in a container inside a Kubernetes cluster to check for cluster
  compliance.

The one-off process is more useful for things like:
* Running in CI/CD pipeline to check code compliance of code in that pipeline.
* Running in cron jobs to check the compliance at regular intervals.
* Running in a container to check the compliance of the container image.

This document details how to run the ccf-agent agent as a service, server or daemon
on Linux, Mac and Windows. For details of how to run as a one-off process see
[here](running_as_a_process.md).

You should read the steps for the particular OS you are interested in. The steps
should be independent of CPU architecture though you should ensure you download
the agent for your chosen architecture.

## Running as a daemon on Linux through `systemd`

In this section we show how to run the ccf-agent agent as a daemon on Linux through
systemd. First let's make sure that your Linux distribution uses systemd. You
can check this by running the following command:

```bash
ls -lh /sbin/init
```
If you have a `systemd` based system it should show a symlink to `systemd`
something like the following:
```
lrwxrwxrwx. 1 root root 22 Oct 15 14:17 /sbin/init -> ../lib/systemd/systemd
```
If you don't have systemd you can check out the section `Running as a daemon on
non-systemd based Linux` below.

### Step 1: Download the ccf-agent agent

Download the ccf-agent agent for your architecture from the [releases] page
[here](https://github.com/https://github.com/compliance-framework/agent/releases)
and place it in a directory of your choice. For example, you can download the
agent for Linux x86_64 as follows:

```bash
ccf-agent_RELEASE=0.1.0
ARCH=x86_64
OS=Linux
curl -LOf https://github.com/compliance-framework/agent/releases/download/v${ccf-agent_RELEASE}/agent_${OS}_${ARCH}.tar.gz
```

Then you need to extract the agent and copy it to a directory of your choice.
For example you can run the following commands:

```bash
tar xvf agent_${OS}_${ARCH}.tar.gz
sudo cp agent /usr/local/bin/ccf-agent
```

### Step 2: Create a systemd service file

Create a systemd service file for the ccf-agent agent. You can use the following:

```bash
sudo tee /etc/systemd/system/ccf-agent.service <<EOF
[Unit]
Description=Continuous Compliance (ccf-agent) Agent
Documentation=https://github.com/continuouscompliance/agent
Wants=network-online.target
After=network.target network-online.target local-fs.target

[Install]
WantedBy=multi-user.target

[Service]
Type=notify
WorkingDirectory=/var/lib/ccf-agent
StateDirectory=ccf-agent
ExecStart=/usr/local/bin/ccf-agent agent -d -c /etc/ccf-agent/config.yaml
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
EOF
```

`WorkingDirectory` and `StateDirectory` give the agent a persistent place for its download caches and its
per-instance state (`.compliance-framework/state/...`: the instance ID). Without
them the agent writes relative to `/`. The state directory must persist across restarts,
otherwise every restart registers a new instance. See
[State directory and instance ID](configuration.md#state-directory-and-instance-id).

Now run the following command to reload the systemd configuration:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ccf-agent
```

You should now be able to start the ccf-agent agent as a service by running the
following:

```bash
sudo systemctl start ccf-agent
```

## Running as a daemon on non-systemd based Linux

If you don't have a systemd based system you can still run the ccf-agent agent as a
daemon by running the following command:

```bash
nohup /path/to/ccf-agent agent -d &
```

You can also lookup how to set this process to run on startup using whatever
init system your Linux distribution uses. All logs are sent to stdout or stderr
and can be redirected to a file if needed and it will terminate on SIGKILL or
SIGINT (or if it panics).

## Running as a service on Mac through `launchd`

TODO

## Running as a service on Windows through Windows services

TODO

## Running as a server/container

Mount a volume for the agent's state and pin it with `CCF_STATE_DIR`: the default state directory is derived from the
config file's absolute path, so a container that mounts its config elsewhere would otherwise get a new instance ID
(R52). In Kubernetes jobs and CI one-shot runs, set `CCF_INSTANCE_ID` to a fixed UUID so repeated runs report as one
instance; one-shot instances are pruned by the API after 24h.

## Running as a serverless process in AWS

TODO

## Running as a serverless process in Azure

TODO

## Running as a serverless process in GCP

TODO
```
