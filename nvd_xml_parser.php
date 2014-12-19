<?php

// if you try to get from remote.
//$url = "https://nvd.nist.gov/download/nvdcve-2002.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2003.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2004.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2005.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2006.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2007.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2008.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2009.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2010.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2011.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2012.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2013.xml"
//$url = "https://nvd.nist.gov/download/nvdcve-2014.xml"
//$xml = file_get_contents($url, false, $context);

if (isset($argv[1])) {
   $xml = $argv[1];
} else {
   exit("error");
}

$data = new SimpleXMLElement($xml);

foreach ($data->entry as $entry) {
    $cve = $entry['name'];
    $cvss = $entry['CVSS_base_score'];

    $range = "";

    if ( (string)$entry->desc->descript['source'] == 'cve' ){
        $desc = $entry->desc->descript;
    }

    if (preg_match('/"/', $desc)) {
        $desc = preg_replace('/\"/', '""', $desc);
    }elseif (preg_match('/,/', $desc)) {    // for Microsoft Excel.
        $desc = preg_replace('/\,/', ',,', $desc);
    }

    foreach($entry->range->children() as $child) {
        $range .= " " . $child->getName();
    }

    print "$cve, ";
    print "$cvss, ";
    print "$range, ";
    print "\"$desc\"\n";

}
?>
