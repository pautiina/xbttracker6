<?php

/* do NOT run this script through a web browser */
if (!isset($_SERVER['argv'][0]) || isset($_SERVER['REQUEST_METHOD'])  || isset($_SERVER['REMOTE_ADDR'])) {
    die('<br><strong>This script is only meant to run at the command line.</strong>');
}

global $config;

$no_http_headers = true;

/* display No errors */
error_reporting(0);

if (!isset($called_by_script_server)) {
    include_once(dirname(__FILE__) . '/../include/global.php');
    array_shift($_SERVER['argv']);
    print call_user_func_array('xbt_status', $_SERVER['argv']);
}

function xbt_status($xbtt_status_url) {

$result_for_url = get_web_page( $xbtt_status_url );
if ( $result_for_url['errno'] != 0 ) {
    cacti_log('ERROR: Invalid URL or timeout for:' . $xbtt_status_url . ' ERROR:' . curl_strerror($result_for_url['errno']), false);
    return "leechers:U peers:U seeders:U torrents:U";
} elseif ( $result_for_url['http_code'] != 200 ) {
    cacti_log('ERROR: Page ' . $xbtt_status_url . ' does not exist or do not have permission', false);
    return "leechers:U peers:U seeders:U torrents:U";
} else {
    $page = $result_for_url['content']; 
    $dom  = new DOMDocument();
    $dom->loadHTML($page);
    $leechers = $dom->getElementsByTagName('td')->item(1)->nodeValue;
    $seeders = $dom->getElementsByTagName('td')->item(3)->nodeValue;
    $peers = $dom->getElementsByTagName('td')->item(5)->nodeValue;
    $torrents = $dom->getElementsByTagName('td')->item(7)->nodeValue;
    return sprintf("leechers:%d seeders:%d peers:%d torrents:%d", $leechers, $seeders, $peers,  $torrents);
}
}

function get_web_page( $url ){
    //- See more at: http://parsing-and-i.blogspot.ru/2009/09/curl-first-steps.html#sthash.A8rDS356.dpuf
    $uagent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)"; 
    $ch = curl_init( $url ); curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); // возвращает веб-страницу 
    curl_setopt($ch, CURLOPT_HEADER, 0); // не возвращает заголовки 
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1); // переходит по редиректам 
    curl_setopt($ch, CURLOPT_ENCODING, ""); // обрабатывает все кодировки 
    curl_setopt($ch, CURLOPT_USERAGENT, $uagent); // useragent 
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 120); // таймаут соединения 
    curl_setopt($ch, CURLOPT_TIMEOUT, 120); // таймаут ответа 
    curl_setopt($ch, CURLOPT_MAXREDIRS, 10); // останавливаться после 10-ого редиректа 
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept-Encoding: gzip', 'Content-Type: text/xml; charset=cp1251'));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $content = curl_exec( $ch ); 
    $err = curl_errno( $ch ); 
    $errmsg = curl_error( $ch ); 
    $header = curl_getinfo( $ch ); 
    curl_close( $ch );
    $header['errno'] = $err; 
    $header['errmsg'] = $errmsg; 
    $header['content'] = $content; 

    return $header;
}
?>

