$Root = Resolve-Path "$PSScriptRoot\..\.."

& "$Root\target\release\sov-operator-cli.exe" `
  -c "$Root\config\operator-cli.yaml" `
  @args

