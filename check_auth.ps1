$files = Get-ChildItem -Path "src\main\java\com\vulnprint\controller" -Filter "*Controller.java"
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    # Matches annotations and mapping, then public returnType methodName(
    $matches = [regex]::Matches($content, '(?s)(?:@[A-Za-z]+(?:\([^)]*\))?\s*)*@(Get|Post|Put|Delete|Patch)Mapping(?:\([^)]*\))?(?:\s*@[A-Za-z0-9_.]+(?:\([^)]*\))?\s*)*\s*public\s+[\w<>\?\[\]\s]+\s+(\w+)\s*\(')
    foreach ($match in $matches) {
        if ($match.Value -notmatch '@PreAuthorize') {
            $name = $file.Name
            $meth = $match.Groups[2].Value
            Write-Host "Missing @PreAuthorize in ${name}: ${meth}"
        }
    }
}
