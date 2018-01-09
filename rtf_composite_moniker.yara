rule rtf_composite_moniker {
   meta:
      ref = "https://justhaifei1.blogspot.co.uk/2017/07/bypassing-microsofts-cve-2017-0199-patch.html"
   strings:
      $header_rtf = "{\\rt" nocase
      $composite_moniker = "0903000000000000C000000000000046" nocase
      $new_moniker = "C6AFABEC197FD211978E0000F8757E2A" nocase
   condition:
      $header_rtf at 0 and $composite_moniker and $new_moniker
}