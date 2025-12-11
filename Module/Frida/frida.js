// Frida 스크립트는 안드로이드 앱의 런타임에 삽입(injection)되어,
// Java/Native 코드의 동작을 실시간으로 감시하고 조작(hooking)하는 역할을 한다.
Java.perform(function() {
    /**
     * @name bytesToString
     * @description 바이트 배열을 사람이 읽을 수 있는 문자열로 변환하는 헬퍼 함수이다.
     * @param {byte[]} bytes - 변환할 바이트 배열
     * @returns {string|null} 변환된 문자열 또는 입력이 null일 경우 null.
     * @reason 안드로이드에서 처리되는 많은 데이터(파일, 네트워크 패킷 등)는 바이트 배열 형태이다.
     * 분석가가 로그를 통해 데이터를 쉽게 이해할 수 있도록 사람이 읽을 수 있는 문자열로 변환하는 역할을 한다.
     * `& 0xff` 연산은 Java의 signed byte(-128~127)를 unsigned byte(0~255)로 변환하여 올바른 문자로 매핑하기 위해 필수적이다.
     */
    function bytesToString(bytes) {
        if (!bytes) return null;
        var result = "";
        for (var i = 0; i < bytes.length; i++) {
            result += String.fromCharCode(bytes[i] & 0xff);
        }
        return result;
    }
    
    /**
     * @name bytesToHex
     * @description 바이트 배열을 16진수(Hex) 문자열로 변환하는 헬퍼 함수이다.
     * @param {byte[]} bytes - 변환할 바이트 배열
     * @returns {string|null} 변환된 16진수 문자열 또는 입력이 null일 경우 null.
     * @reason 암호화된 데이터나 바이너리 데이터처럼 일반 문자열로 표현할 수 없는 데이터를 분석할 때 유용하다.
     * 16진수 표현은 데이터의 원본 형태를 손실 없이 정확하게 파악하는 데 필수적이다.
     */
    function bytesToHex(bytes) {
        if (!bytes) return null;
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            var byte = bytes[i] & 0xFF;
            hex += ('0' + byte.toString(16)).slice(-2);
        }
        return hex;
    }

    // 스크립트가 성공적으로 앱 프로세스에 주입되었음을 콘솔에 출력하여 분석가에게 알려준다.
    console.log('[+] Simple Reconnaissance Script Loaded.');

    // --- 1. Data Storage (데이터 저장) ---
    // 앱이 기기 내부에 어떤 데이터를 저장하는지 감시한다. 주로 설정, 토큰, 사용자 정보 등이 저장된다. (CWE-312 관련)
    try {
        // 'android.app.SharedPreferencesImpl$EditorImpl' 클래스에 대한 JavaScript 래퍼 객체를 가져온다.
        // SharedPreferences는 안드로이드에서 간단한 Key-Value 데이터를 저장하는 데 사용되는 주요 메커니즘이다.
        var sharedPrefsEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        
        // putString 메소드를 후킹하여 어떤 Key와 Value가 저장되는지 감시한다.
        sharedPrefsEditor.putString.implementation = function(key, value) {
            // SharedPreferences에 쓰이는 모든 문자열 데이터를 'KEY'와 'VALUE' 형식으로 콘솔에 출력한다.
            // 이를 통해 개인정보, 인증 토큰 등 민감 정보가 평문으로 저장되는지 확인할 수 있다.
            console.log('[SharedPreferences] WRITE -> KEY: "' + key + '", VALUE: "' + value + '"');
            
            // 원래의 putString 메소드를 호출하여 앱이 정상적으로 동작하도록 한다.
            return this.putString(key, value);
        };
    } catch (e) { /* 앱이 해당 클래스를 사용하지 않을 경우 오류가 발생할 수 있으므로 무시한다. */ }

    // --- 2. File I/O (파일 입출력) ---
    // 앱이 파일 시스템에 어떤 데이터를 기록하는지 감시한다. 로그 파일, 캐시 데이터, 다운로드된 콘텐츠 등을 확인할 수 있다. (CWE-312 관련)
    try {
        // Java의 'java.util.Arrays' 클래스를 가져온다. 바이트 배열의 일부를 복사하는 데 사용된다.
        var Arrays = Java.use('java.util.Arrays');
        // 'java.io.FileOutputStream' 클래스의 write 메소드에 대한 JavaScript 래퍼 객체를 가져온다.
        var fos_write = Java.use('java.io.FileOutputStream').write;

        // FileOutputStream.write(byte[] buffer, int offset, int count) 메소드를 후킹한다.
        fos_write.overload('[B', 'int', 'int').implementation = function(buffer, offset, count) {
            // 실제로 파일에 쓰이는 데이터 부분(slice)만 정확히 추출하기 위해 Arrays.copyOfRange를 사용한다.
            var dataSlice = Arrays.copyOfRange(buffer, offset, offset + count);
            // 추출된 바이트 배열을 문자열로 변환하고, 출력 불가능한 문자는 '.'으로 치환하여 로그 가독성을 높인다. (최대 100자)
            var dataPreview = bytesToString(dataSlice).replace(/[^\x20-\x7E]/g, '.').substring(0, 100);
            // 파일에 쓰이는 데이터의 크기와 미리보기 내용을 콘솔에 출력한다.
            // 이를 통해 민감 정보가 암호화되지 않은 채 파일로 저장되는지 파악할 수 있다.
            console.log('[FileIO] Write -> ' + count + ' bytes | DATA: "' + dataPreview + '..."');
            
            // 원래의 write 메소드를 호출하여 파일 쓰기 작업이 정상적으로 수행되도록 한다.
            return this.write(buffer, offset, count);
        };
    } catch (e) { /* Ignore */ }

    // --- 3. Encoding (인코딩) ---
    // 데이터가 네트워크로 전송되거나 저장되기 전에 어떻게 인코딩되는지 확인한다. (CWE-798 관련)
    try {
        // 'android.util.Base64' 클래스를 가져온다. 안드로이드에서 흔히 사용되는 인코딩 방식이다.
        var base64 = Java.use('android.util.Base64');
        
        // Base64.encodeToString(byte[] input, int flags) 메소드를 후킹한다.
        base64.encodeToString.overload('[B', 'int').implementation = function(input, flags) {
            // 원래 메소드를 먼저 호출하여 Base64 인코딩 결과를 얻는다.
            var result = this.encodeToString(input, flags);
            // 인코딩되기 전의 원본 데이터 미리보기를 문자열로 변환하여 콘솔에 출력한다. (최대 100자)
            // 어떤 데이터가 Base64로 인코딩되어 숨겨지는지 파악할 수 있으며, 이는 종종 API Key나 Secret을 숨기는 데 사용된다.
            var dataPreview = bytesToString(input).substring(0, 100);
            console.log('[Encoding] Base64 Encoded -> DATA: "' + dataPreview + '..."');
            
            // 원래의 인코딩된 결과를 반환한다.
            return result;
        };
    } catch (e) { /* Ignore */ }
    
    // --- 4. Network (네트워크 통신) ---
    // 앱이 외부 서버와 어떤 통신을 하는지 감시한다. API 호출, 데이터 전송 등을 파악하는 데 매우 중요하다. (CWE-295 관련)
    try {
        // 'okhttp3.RealCall' 클래스를 가져온다. OkHttp3는 안드로이드에서 널리 쓰이는 네트워킹 라이브러리이다.
        var RealCall = Java.use("okhttp3.RealCall");
        
        // 동기(Synchronous) 방식의 네트워크 요청을 감시하기 위해 execute 메소드를 후킹한다.
        RealCall.execute.implementation = function() {
            var request = this.request();
            // 요청 메소드(GET, POST 등)와 전체 URL을 콘솔에 출력한다.
            console.log('[Network] OkHttp3 Request (SYNC) -> ' + request.method() + ' ' + request.url().toString());
            return this.execute();
        };
        
        // 비동기(Asynchronous) 방식의 네트워크 요청을 감시하기 위해 enqueue 메소드를 후킹한다.
        RealCall.enqueue.implementation = function(callback) {
            var request = this.request();
            console.log('[Network] OkHttp3 Request (ASYNC) -> ' + request.method() + ' ' + request.url().toString());
            return this.enqueue(callback);
        };
    } catch (e) { /* OkHttp3를 사용하지 않는 앱을 위해 오류를 무시하고 다음 후킹을 시도한다. */ }

    try {
        // 'java.net.HttpURLConnection' 클래스를 가져온다. 표준 Java 네트워크 라이브러리이다.
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        // getOutputStream 메소드를 후킹한다. 이 메소드는 POST, PUT 등 요청 본문(body)이 있을 때 호출된다.
        HttpURLConnection.getOutputStream.implementation = function() {
            var url = this.getURL().toString();
            // 요청 메소드와 URL을 출력하여 어떤 서버로 데이터를 보내려는지 파악한다.
            console.log('[Network] HttpURLConnection -> ' + this.getRequestMethod() + ' ' + url);
            return this.getOutputStream();
        };
    } catch (e) { /* Ignore */ }
    
    // --- 5. WebView ---
    // 앱 내에 내장된 웹 브라우저(WebView)가 어떤 URL을 로드하는지 감시한다. (CWE-295 관련)
    try {
        // 'android.webkit.WebView' 클래스를 가져온다.
        var WebView = Java.use('android.webkit.WebView');
        
        // WebView.loadUrl(String url) 메소드를 후킹한다.
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            // WebView가 로드하는 URL을 콘솔에 출력한다.
            // 이를 통해 앱이 사용자에게 보여주는 웹 페이지뿐만 아니라, 백그라운드에서 몰래 로드하는 광고나 트래킹 URL도 파악할 수 있다.
            console.log('[Network] WebView.loadUrl -> URL: ' + url);
            
            // 원래의 loadUrl 메소드를 호출하여 웹 페이지가 정상적으로 로드되도록 한다.
            this.loadUrl.overload('java.lang.String').call(this, url);
        };
    } catch (e) { /* 앱이 WebView를 사용하지 않을 경우를 대비해 오류를 무시한다. */ }

    // --- 6. Cryptography (암호화) ---
    // 앱의 암호화 및 복호화 과정을 감시하여 어떤 데이터가 어떻게 처리되는지 확인한다.
    try {
        // 'javax.crypto.Cipher' 클래스를 가져온다. Java에서 암호화/복호화의 핵심 역할을 한다.
        var Cipher = Java.use('javax.crypto.Cipher');
        // Cipher 객체의 상태(암호화/복호화 모드, 키)를 저장하기 위한 Map 객체를 생성한다.
        var cryptoMap = new Map();

        // Cipher.init(int opmode, Key key) 메소드를 후킹하여 암호화/복호화 모드와 사용되는 키를 파악한다.
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            // opmode 값에 따라 'ENCRYPT'(1) 또는 'DECRYPT'(2) 모드를 결정한다.
            var mode = (opmode == 1) ? 'ENCRYPT' : (opmode == 2) ? 'DECRYPT' : 'UNKNOWN';
            // 암호화에 사용된 키를 16진수 문자열로 변환하여 기록한다. 이 키를 통해 나중에 데이터를 복호화해볼 수 있다.
            var keyHex = bytesToHex(key.getEncoded());
            // 현재 Cipher 객체(this.hashCode())를 키로 사용하여 모드와 키 정보를 cryptoMap에 저장한다.
            // init과 doFinal은 다른 시점에 호출되므로, 상태를 연결하기 위해 이 Map이 필요하다.
            cryptoMap.set(this.hashCode(), { mode: mode, key: keyHex });
            console.log('[Crypto] Cipher.init -> MODE: ' + mode + ' | KEY: ' + keyHex);
            
            // 원래의 init 메소드를 호출한다.
            return this.init.overload('int', 'java.security.Key').call(this, opmode, key);
        };
        
        // 실제 암호화/복호화가 수행되는 doFinal(byte[] input) 메소드를 후킹한다.
        Cipher.doFinal.overload('[B').implementation = function(input) {
            // 원래 doFinal을 먼저 호출하여 암호화/복호화된 결과 데이터를 얻는다.
            var result = this.doFinal.overload('[B').call(this, input);
            // cryptoMap에서 현재 Cipher 객체에 해당하는 모드 정보를 가져온다.
            var details = cryptoMap.get(this.hashCode()) || { mode: 'UNKNOWN' };
            // 작업 모드, 입력 데이터(원본), 출력 데이터(결과)를 16진수로 변환하여 콘솔에 출력한다. (최대 50자)
            // 이를 통해 어떤 데이터가 암호화되어 저장/전송되는지, 또는 어떤 데이터가 복호화되어 사용되는지 직접 확인할 수 있다.
            console.log('[Crypto] Cipher.doFinal -> MODE: ' + details.mode + ' | INPUT(hex): ' + bytesToHex(input).substring(0, 50) + '... | OUTPUT(hex): ' + bytesToHex(result).substring(0, 50) + '...');
            
            // 결과 데이터를 반환한다.
            return result;
        };
    } catch (e) { /* Ignore */ }
    
    // --- 7. Reflection (리플렉션) ---
    // 런타임에 동적으로 메소드를 호출하는 리플렉션 행위를 감시한다. 난독화 우회나 숨겨진 기능을 실행하는 데 자주 사용된다. (CWE-502 관련)
    try {
        // 'java.lang.reflect.Method' 클래스를 가져온다.
        var Method = Java.use('java.lang.reflect.Method');
        
        // 메소드를 동적으로 호출하는 invoke 메소드를 후킹한다.
        Method.invoke.implementation = function(obj, args) {
            var methodName = this.getName();
            // 어떤 메소드가 리플렉션을 통해 호출되는지 그 이름을 콘솔에 출력한다.
            // 악성코드는 종종 정적 분석을 피하기 위해 핵심적인 악성 행위를 리플렉션으로 숨긴다. 이 후킹은 그런 시도를 탐지하는 데 도움이 된다.
            console.log('[Runtime] Reflection -> Method.invoke: ' + methodName);
            
            // 원래 invoke를 호출한다.
            return this.invoke(obj, args);
        };
    } catch (e) { /* Ignore */ }

    // --- 8. Dynamic Code Loading (동적 코드 로딩) ---
    // 앱이 실행 중에 새로운 코드를 로드하는 행위를 감시한다. 악성코드가 추가 모듈을 다운로드하여 실행하는 전형적인 방식이다. (CWE-489 관련)
    try {
        // 'dalvik.system.DexClassLoader' 클래스를 가져온다. 안드로이드에서 외부 DEX(Dalvik Executable) 파일을 로드하는 데 사용된다.
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        
        // DexClassLoader의 생성자($init)를 후킹한다.
        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            // 로드하려는 DEX 파일의 경로를 콘솔에 출력한다.
            // 앱이 서버에서 악성 DEX 파일을 다운로드하여 로드하는 경우, 이 로그를 통해 파일의 위치와 존재를 파악할 수 있다.
            console.log('[Runtime] DynamicCode -> DexClassLoader loaded: ' + dexPath);
            
            // 원래 생성자를 호출하여 코드 로딩이 정상적으로 진행되도록 한다.
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) { /* Ignore */ }

});