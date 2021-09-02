<?php

require_once "../vendor/autoload.php";
use Emarref\Jwt\Claim;

class  JWTAuth
{
    private static $Instance = null;
    private $Audience = ['app', 'web'];
    private $exp=3600;//默认过期时间秒
    private $uid;//默认过期时间秒
    private $secret = "@#$%^&(*&$#@$^*SDDASW";//安全key,服务器存储

    //用户ID
    public static function setUid($uid)
    {
        $self=new self();
        $self->uid=$uid;
        return $self;
    }

    //设置安全key
    public function setSecret(string $secret)
    {
        $this->secret = $secret;
        return $this;
    }

    //设置过期时间,默认为秒
    public function setExp(int $exp)
    {
        $this->exp = $exp;
        return $this;
    }

    private function jwt()
    {
        $algorithm = new Emarref\Jwt\Algorithm\Hs256($this->secret);
        return Emarref\Jwt\Encryption\Factory::create($algorithm);
    }


    /*
     * @$retString  为true,返回字符串
     */
    public  function createToken()
    {
        $token = new Emarref\Jwt\Token();

// Standard claims are supported
        $token->addClaim(new Claim\Audience(['app', 'web']));
        $token->addClaim(new Claim\Issuer($_SERVER['HTTP_HOST']));//
        $token->addClaim(new Claim\JwtId($this->uid));//
        $token->addClaim(new Claim\IssuedAt(time()));//签发时间
        $token->addClaim(new Claim\NotBefore(time()));//定义某个时间前不可用
        $token->addClaim(new Claim\Expiration(strtotime("+{$this->exp} second")));//过期时间
        $token->addClaim(new Claim\Subject('user_1'));//所面向的用户

        // Custom claims are supported
        $token->addClaim(new Claim\PublicClaim('xiali', 'xiali'));
        return (new Emarref\Jwt\Jwt())->serialize($token, $this->jwt());

    }


    public  function  validate($token)
    {
        try {
            $sor = explode('.', $token);
            $arr = @json_decode(base64_decode($sor[1]), true);
            $context = new Emarref\Jwt\Verification\Context($this->jwt());
            @$context->setAudience($arr['aud'][0]);
            @$context->setIssuer($arr['iss']);
            @$context->setSubject($arr['sub']);
            $token = (new Emarref\Jwt\Jwt())->deserialize($token);
            (new Emarref\Jwt\Jwt())->verify($token, $context);
            return $arr;
        } catch (Exception $e) {
            return false;
        }
    }

}

$jwt=new JWTAuth();
$jwt2=new JWTAuth();

$token= $jwt->setUid(999)->setSecret("13523r4r")->createToken();//生成token

$jwt2->setSecret("13523r4r")->validate($token); //验证成功返回数组,失败返回false


