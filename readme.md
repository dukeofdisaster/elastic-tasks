# elastic-tasks
A utility for monitoring elastic tasks that exceed a given threshold.
Takes a yaml config and generates a config with encrypted creds and priv key.

NOTE: On a production cluster it can be normal to have tasks running for
much longer than 2m; ML jobs can run a year for example, thuss the use of the
ignored list. 

## Example usage
1. Build the binary
1. Generate a config: ```./main -g```
1. Create a cron job: ```*/1 * * * * /opt/taskwatcher/taskwatcher -c /opt/taskwatcher/taskwatcher.yaml```
1. Do whatever you want with ndjson log file

## SAMPLE CONFIG
Sample config showing crypt+base64 encoded creds in config. When -g option is ran, the key name
will be the sha256sum of the key. 

```yaml
log:
  path: /var/log/tasks/tasks.json
task:
  minimum: 2m
  ignored:
  - SomeTaskIdHere
  - sldfEJSfkjsdflkjs:10000
cluster:
  user: Nl8tWNl/ba4eDHDMbldxJZZAQy2yTLXGLLv/3gMpsjZOhd2N/og5fckbkaUd+Vhc6jncYaGZsObQFqdmI7wSo9g3tH9eGPMUXhtRgl8NHuVeTvRRHgtJfV1AiT69nxEZVsKAlZQBFOk0Ve4pOJALC8YMVIBRCmVnCimnv+g0j+o6Qx6v58cLspjlopHjQNnvUCzz3LYyID9HUEYF4WzwiAgoqOnFgbCzg==
  password: prt+x5htVwrghJ8ugUALFLZMdgTaaY6xlU2OdpRJbH+/3V3goYrjorISi2RTY77jWUj4EmdeFLf40GxsUSYbH9dko2S+GQQ7/MIpTfoWwkLhsQoXW9WPN1XHdV+biFJDkpWwzFhGnOZ+0XsXqIu3njHC0N0AwA19LSDij2a6Hz2f9tkKzUzzmKzwIHxpk1KeULCA==
  encrypted_creds: true
  keypath: /some/dir/some.key
  auth: true
  url: http://192.168.2.20:9200
```


## TODO
- Add application logging.
- Consider Additional meta fields for the loggableTask
- Add better error handling.
- Improve config
