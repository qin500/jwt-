# JWT使用


### 生成token,和验证token

````
$jwt=new JWTAuth();
$jwt2=new JWTAuth();

$token= $jwt->setUid(999)->setSecret("13523r4r")->createToken();//生成token

$jwt2->setSecret("13523r4r")->validate($token); //验证成功返回数组,失败返回false
````

[元仓库](https://github.com/emarref/jwt)


