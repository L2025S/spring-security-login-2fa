package se.iths.lw.springsecuritylogin2fa.service;


import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Service
public class TwoFactorService {

    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

    public String generateSecret(){
        GoogleAuthenticatorKey googleAuthenticatorKey = googleAuthenticator.createCredentials();
        return googleAuthenticatorKey.getKey();
    }

    public String getOtpAuthUri(String secret, String username, String issuer){
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer,username, secret, issuer);
    }

    public byte[] generateQrCodeImage(String text, int width, int height){
        try {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE,width, height);

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix,"PNG", pngOutputStream);
        return pngOutputStream.toByteArray();

        } catch (WriterException | IOException e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    public boolean verifyTotpCode(String secret, int code){
        return
                googleAuthenticator.authorize(secret, code);
    }
}
