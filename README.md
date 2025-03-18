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

The tracer will also record various metrics, that can be queried by the following command:
```
$ curl localhost:8080/metrics --silent | grep package
# HELP package_in_use_collisions Gauge for amount of collisions in files
# TYPE package_in_use_collisions gauge
package_in_use_collisions{type="files"} 0
package_in_use_collisions{type="strings"} 0
# HELP package_in_use_map_size Gauge for map size
# TYPE package_in_use_map_size gauge
package_in_use_map_size{type="files"} 2938
package_in_use_map_size{type="strings"} 1061
```
