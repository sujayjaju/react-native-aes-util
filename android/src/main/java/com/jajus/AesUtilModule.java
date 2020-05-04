package com.jajus;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

package com.reactnative.crypto;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Hex;
import android.util.Base64;
import android.util.Log;
import com.google.gson.Gson;


public class AesUtilModule extends ReactContextBaseJavaModule {

	public static final String ALGORITHM = "AES";
	public static final String ALGO_TRANSFORMATION = "AES/GCM/NoPadding";
	public static final int TAG_LENGTH_BITS = 128;
	public static final int IV_LENGTH_BYTES = 16;
	public static final String HASH_ALGO = "SHA1PRNG";

    private final ReactApplicationContext reactContext;

    public AesUtilModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "AesUtil";
    }

	@ReactMethod
	public void encrypt(String aClearText, String aSecretKey, String aAad, Promise aPromise) {
		try {
			if (aSecretKey == null || "".equals(aSecretKey)) {
				Log.e("secretKey====>>>>", "secretKey is null");
				aPromise.reject("INVALID_PARAMETER", "secretKey MUST not be null");
			}

      byte[] fResult = null;
			try {
				Cipher fCipher = Cipher.getInstance(ALGO_TRANSFORMATION);
				SecretKeySpec fKeySpec = new SecretKeySpec(Base64.decode(aSecretKey, Base64.NO_WRAP), ALGORITHM);

				SecureRandom fRandom = SecureRandom.getInstance(HASH_ALGO);
				byte[] fInitVector = new byte[IV_LENGTH_BYTES];
				fRandom.nextBytes(fInitVector);

				GCMParameterSpec fGcmParamSpec = new GCMParameterSpec(TAG_LENGTH_BITS, fInitVector);
				fCipher.init(Cipher.ENCRYPT_MODE, fKeySpec, fGcmParamSpec, new SecureRandom());

				if(aAad != null && !"".contentEquals(aAad))
				{
					fCipher.updateAAD(aAad.getBytes());
				}

        byte[] fEncryptedBytes = fCipher.doFinal(aClearText.getBytes("UTF-8"));
        ByteBuffer byteBuffer = ByteBuffer.allocate(fInitVector.length + fEncryptedBytes.length);
        byteBuffer.put(fInitVector);
        byteBuffer.put(fEncryptedBytes);
        fResult = byteBuffer.array();

			} catch (Exception e) {
				e.printStackTrace();
				aPromise.reject(e);
			}
			String fCipherText = Base64.encodeToString(fResult, Base64.NO_WRAP);
			aPromise.resolve(fCipherText);
		} 
		catch (Exception e) {
			e.printStackTrace();
			aPromise.reject(e);
		}
	}

	@ReactMethod
	public void decrypt(String aCipherText, String aSecretKey, String aAad, Promise aPromise) {
		try {
			if (aSecretKey == null || "".equals(aSecretKey)) {
				Log.e("secretKey====>>>>", "secretKey is null");
				aPromise.reject("INVALID_PARAMETER", "secretKey MUST not be null");
			}
			
			Cipher fCipher = Cipher.getInstance(ALGO_TRANSFORMATION);
			SecretKeySpec fKeySpec = new SecretKeySpec(Base64.decode(aSecretKey, Base64.NO_WRAP), ALGORITHM);

			byte[] fMessageBytes = Base64.decode(aCipherText, Base64.NO_WRAP);

			byte[] fInitVector = new byte[IV_LENGTH_BYTES];
			ByteBuffer fByteBuffer = ByteBuffer.wrap(fMessageBytes);
			fByteBuffer.get(fInitVector);
			byte[] fCipherText = new byte[fByteBuffer.remaining()];
			fByteBuffer.get(fCipherText);

			GCMParameterSpec fGcmParamSpec = new GCMParameterSpec(TAG_LENGTH_BITS, fInitVector);
			fCipher.init(Cipher.DECRYPT_MODE, fKeySpec, fGcmParamSpec, new SecureRandom());
			
			if(aAad != null && !"".contentEquals(aAad))
			{
				fCipher.updateAAD(aAad.getBytes());
			}
			
			byte[] fDecryptedBytes = fCipher.doFinal(fCipherText);
			String fOriginalString = new String(fDecryptedBytes, "UTF-8");
			aPromise.resolve(fOriginalString);
		} 
		catch (Exception e) {
			e.printStackTrace();
			aPromise.reject(e);
		}
	}
	
	@ReactMethod
	public void decodeJwt(String aJwt, String aKey, Promise aPromise) {
		try {
			if (aJwt == null || "".equals(aJwt)) {
				Log.e("aJwt====>>>>", "aJwt is null");
				aPromise.reject("INVALID_PARAMETER", "aJwt MUST not be null");
			}
			
			Key fHmacKey = null;
			
			if(aKey != null && !"".equals(aKey))
			{
				String s = new String(Hex.encodeHex(DigestUtils.sha256(aKey)));
				fHmacKey = Keys.hmacShaKeyFor(s.getBytes("UTF-8"));
			}
			
			JwtParser fParser = Jwts.parser();
			
			Claims fClaims = null;
			
			if(fHmacKey != null)
			{
				fClaims = fParser
						.setSigningKey(fHmacKey)
						.parseClaimsJws(aJwt)
						.getBody();
			}
			else
			{
				fClaims = fParser
						.parseClaimsJwt(aJwt)
						.getBody();
			}
			
      		Gson fGson = new Gson();
      		String fJsonString = fGson.toJson(fClaims);
			aPromise.resolve(fJsonString);

		} catch (Exception e) {
			e.printStackTrace();
			aPromise.reject(e);
		}
	}
	
	@ReactMethod
	public void signJwt(String aJwt, String aKey, Promise aPromise) {
		try {
			if (aJwt == null || "".equals(aJwt)) {
				Log.e("aJwt====>>>>", "aJwt is null");
				aPromise.reject("INVALID_PARAMETER", "aJwt MUST not be null");
			}
			if (aKey == null || "".equals(aKey)) {
				Log.e("aKey====>>>>", "aKey is null");
				aPromise.reject("INVALID_PARAMETER", "aKey MUST not be null");
			}
			
			Key fHmacKey = null;
			
			if(aKey != null && !"".equals(aKey))
			{
        String s = new String(Hex.encodeHex(DigestUtils.sha256(aKey)));
				fHmacKey = Keys.hmacShaKeyFor(s.getBytes("UTF-8"));
			}
			
			JwtParser fParser = Jwts.parser();
			
			Claims fUnsignedJwtClaims = fParser.parseClaimsJwt(aJwt).getBody();
			
			JwtBuilder fBuilder = Jwts.builder();
			
			String fSignedJwt = Jwts.builder()
					.setClaims(fUnsignedJwtClaims)
					.signWith(SignatureAlgorithm.HS256, fHmacKey)
					.compact();
			
			aPromise.resolve(fSignedJwt);

		} catch (Exception e) {
			e.printStackTrace();
			aPromise.reject(e);
		}
	}
}