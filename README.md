# package-in-use-detector

A tool for detecting which files are being accessed by running processes in a Linux system using eBPF technology.

## Quick Start

Start a nix shell with all required dependencies:

```
$ nix develop
```

Run the tracer to start collecting file access data:

```
$ make run-tracer
```

Find out which files are being accessed by processes using the `file_access` map:

```
$ bpftool map dump name file_access | jq '.[0]'
{
  "key": {
    "mnt_ns": 0,
    "pid": 180018,
    "process_start_time": 200799492666304,
    "file_id": 1205480266
  },
  "value": {
    "counter": 0
  }
}
```

Use the `file_id` to get the file information from the `files` map:

```
$ bpftool map dump name files | jq '.[] | select(.key.hash==1205480266)'
{
  "key": {
    "hash": 1205480266
  },
  "value": {
    "path": {
      "parts": [
        1668248176,
        789273588,
        7628142,
        1414145215,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      ]
    },
    "collision_counter": 0
  }
}
```
