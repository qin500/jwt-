<?php
//ini_set('date.timezone','PRC');

//date_default_timezone_set("PRC");

require '../vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validator;
trait CreateToken{
    private static $instance;
    private $token;
    private $iss='http://localhost/demo/demo/jwt/src/index.php';
    private $aud='work_server';
    private $uid;
    private $secrect='$afas$#$%4534@35we#%$#%^%$&$@@%#$%';
    private $decodeToken;

    public function config(){
        return Configuration::forSymmetricSigner(
        // 您可以使用任何 HMAC 变体（256、384 和 512）
            new Sha256(),
            // 用您自己的密钥替换下面的值！
            InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
        // 如果需要，您还可以通过在此处提供额外参数来覆盖 JOSE 编码器解码器
        );
    }
    public function setUid($uid){
        $this->uid=$uid;
        return $this;
    }

    public function CreateToken($usedAfterTime=null,$expiresAt=null){
        $now   = new DateTimeImmutable();
//
        $usedAfterTime=new DateTimeImmutable();
//        $expiresAt=new DateTimeImmutable("2021-09-02 08:56:09.960371");
        $usedAfterTime=$usedAfterTime ?? $now->modify('+1 minute');

//        echo $usedAfterTime->format('Y-m-d H:i:s.u') . "----------------------";
        $config=$this->config();

        $token = $config->builder()
            // Configures the issuer (iss claim)
            ->issuedBy($this->iss)
            // Configures the audience (aud claim)
            ->permittedFor($this->aud)
            // Configures the id (jti claim)
            ->identifiedBy('4f1g23a12aa')
            // 配置令牌发出的时间(iat claim)
            ->issuedAt($now)
            // 配置令牌可以使用的时间（nbf 声明）
            ->canOnlyBeUsedAfter($usedAfterTime)
            // 配置token的过期时间（exp claim）
            ->expiresAt($expiresAt ?? $now->modify('+1 hour'))
            // 配置一个名为“uid”的新声明
            ->withClaim('uid', $this->uid)
            // 配置一个名为“foo”的新标头
            ->withHeader('foo', 'bar')
            // 构建一个新的令牌
            ->getToken($config->signer(), $config->signingKey());
        echo base64_decode("eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L2RlbW8vZGVtby9qd3Qvc3JjL2luZGV4LnBocCIsImF1ZCI6Indvcmtfc2VydmVyIiwianRpIjoiNGYxZzIzYTEyYWEiLCJpYXQiOjE2MzA1NTUxODcuMjI3MTk2LCJuYmYiOjE2MzA1NDAzNzcuNDYwMzksImV4cCI6MTYzMDU1ODc4Ny4yMjcxOTYsInVpZCI6Mn0");
        var_dump($token->toString());
        return $token;
    }
}



final class MyCustomTokenValidator implements Validator
{
    use CreateToken;//继承

    // implement all methods
    public function assert(\Lcobucci\JWT\Token $token, Constraint ...$constraints): void
    {



        // TODO: Implement assert() method.
    }


    public function validate(\Lcobucci\JWT\Token $token, Constraint ...$constraints): bool
    {
        // TODO: Implement validate() method.
        $u=new \Lcobucci\JWT\Validation\Constraint\PermittedFor("work_server");
        $config=Configuration::forSymmetricSigner(new Sha256(),
            // 用您自己的密钥替换下面的值！
            InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw='));
        //解析头部
        $config->parser()->parse($token->toString());
//        var_dump($config);
        return  false;
    }
}

class JWTAuth  {
    use CreateToken;
    public string  $u ="44 ;";
    public static function getInstance(){
        if(is_null(self::$instance)){
            self::$instance=new self();
        }
        return self::$instance;
    }

    private function __construct()
    {

    }

    private function __clone()
    {
        // TODO: Implement __clone() method.
    }

    /*
     * 生成一个toKen
     */


    public function getToString(){
        return $this->CreateToken()->toString();
    }


    /*
     * 解析token
     */
    public function ParseToKenSting(String $ToKenString){
        $config=$this->config();
//        $config->setParser($config);
        $token=$config->parser()->parse($ToKenString);
//         $token->headers(); // 解析token第一部分
        $uuuu=  $token->claims()->get('iat'); // 解析token第二部分
        var_dump($uuuu);
        var_dump(date('m/d/Y H:i:s',));
        return $uuuu;
    }

    public function Verify($token){

        $config=$this->config();
        $config->parser()->parse($token->toString());
        //验证jwt id是否匹配


        $validate_aud=new \Lcobucci\JWT\Validation\Constraint\PermittedFor($this->aud );
        $config->setValidationConstraints($validate_aud);

        $constraints=$config->validationConstraints();
        $config->setValidator(new MyCustomTokenValidator());
        $bool=$config->validator()->validate($token,...$constraints);
//        var_dump($constraints);
//        var_dump($bool);

    }


}


echo "<pre>";

$jwt=JWTAuth::getInstance();
//$token= $jwt->setUid(2)->CreateToken();
//echo $token->toString();
$mytoken="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImZvbyI6ImJhciJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L2RlbW8vZGVtby9qd3Qvc3JjL2luZGV4LnBocCIsImF1ZCI6Indvcmtfc2VydmVyIiwianRpIjoiNGYxZzIzYTEyYWEiLCJpYXQiOjE2MzA1NTYyNzkuNTg2MDYxLCJuYmYiOjE2MzA1NTYyNzkuNTg2MDY1LCJleHAiOjE2MzA1NTk4NzkuNTg2MDYxLCJ1aWQiOjJ9.Cf23AQzoaCp9kvc7yfkHyfZo_YVEfo8CjQ5Nh-04hxk";

$arr=$jwt->ParseToKenSting($mytoken);
var_dump($arr);

//$jwt->Verify($token);



//print_r(base64_decode("eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L2RlbW8vZGVtby9qd3Qvc3JjL2luZGV4LnBocCIsImF1ZCI6Indvcmtfc2VydmVyIiwianRpIjoiNGYxZzIzYTEyYWEiLCJpYXQiOjE2MzA1NDgzMDkuMjM2MDc1LCJuYmYiOjE2MzA1NDgzNjkuMjM2MDc1LCJleHAiOjE2MzA1NTU1MDkuMjM2MDc1LCJ1aWQiOjJ9"));

















echo "</pre>";