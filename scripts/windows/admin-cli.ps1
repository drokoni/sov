$Root = Resolve-Path "$PSScriptRoot\..\.."

& "$Root\target\release\sov-admin-cli.exe" `
  -c "$Root\config\admin-cli.yaml" `
  @args

