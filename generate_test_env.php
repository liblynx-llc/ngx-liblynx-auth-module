<?php
/*
 *  This generates the test.env file containing JWTs for testing
 */

//this is the IP the test nginx docker environment will see
$valid_ip=get_local_ip();

//this is just intended to provide a token with an IP nginx isn't expecting
$bad_ip='10.0.0.1';

//this secrect must match the one in test-liblynx-nginx.conf
$secret='00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF';



$fp=fopen('test.env', 'w');
comment($fp, "generated by generate_test_env.php\n");


$data=[
  'exp'=>time()+86400*365*10,
  'ip'=>$valid_ip,
  'sub'=>'test',
  'known' => true
];
jwt($fp, 'VALID_JWT', $data, $secret);

$data=[
  'exp'=>time()-3600,
  'ip'=>$valid_ip,
  'sub'=>'test',
  'known' => true
];
jwt($fp, 'EXPIRED_JWT', $data, $secret);


$data=[
  'exp'=>time()+86400*365*10,
  'ip'=>$bad_ip,
  'sub'=>'test',
  'known' => true
];
jwt($fp, 'BAD_IP_JWT', $data, $secret);


$data=[
  'exp'=>time()+86400*365*10,
  'ip'=>$valid_ip,
  'abcd'=>1,
  'known' => true
];
jwt($fp, 'ABCD_JWT', $data, $secret);

$data=[
  'exp'=>time()+86400*365*10,
  'ip'=>$bad_ip,
  'sub'=>0,
  'known' => false
];
jwt($fp, 'ANON_JWT', $data, $secret);

fclose($fp);

function jwt($fp, $name, $data, $secret)
{
    $jwt=generate_jwt($data, $secret);

    comment($fp, "data=".json_encode($data));
    comment($fp, "secret=$secret");
    fwrite($fp, "$name=$jwt\n\n");
}

function comment($fp, $comment)
{
    fwrite($fp, "# $comment\n");
}

function base64url_encode($data)
{
    // First of all you should encode $data to Base64 string
    $b64 = base64_encode($data);

    // Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
    if ($b64 === false) {
      return false;
    }

    // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
    $url = strtr($b64, '+/', '-_');

    // Remove padding character from the end of line and return the Base64URL result
    return rtrim($url, '=');
}

function generate_jwt($data, $secret)
{
    $hdr=[
        'alg'=>'HS256',
        'typ'=>'JWT'
    ];

    $jhdr=json_encode($hdr);
    $jdata=json_encode($data);

    $bhdr=base64url_encode($jhdr);
    $bdata=base64url_encode($jdata);

    $hash=hash_hmac ('sha256' , $bhdr.'.'.$bdata , $secret, true);

    return $bhdr.'.'.$bdata.'.'.base64url_encode($hash);
}

function get_local_ip()
{
    //parse last line of /etc/hosts
    $hosts=file('/etc/hosts');
    $last=array_pop($hosts);
    $parts=explode("\t", $last);
    return $parts[0];
}
