/**
 * Much of this code was stolen from this Stack Overflow post:
 *  http://stackoverflow.com/questions/3939447/how-to-encrypt-a-string-stream-with-bouncycastle-pgp-without-starting-with-a-fil
 *
 * In addition to the java versions of this lump of code, that have been floating around on the internet:
 *  https://gist.github.com/1954648
 *
 * Thanks to everyone who has posted on the topic of Bouncy Castle's PGP Library.
 */

package org.sgonyea.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class Decryptor {

  private PGPSecretKeyRingCollection _privateKeys;
  private PGPPublicKeyRingCollection _publicKeys;

  private String passphrase;

  public Decryptor() { }
  public Decryptor(PGPSecretKeyRingCollection privateKeys) {
    setPrivateKeys(privateKeys);
  }

  /**
   * Accessor and Attribute Helper Methods
  **/
  public PGPSecretKeyRingCollection getPrivateKeys() {
    return _privateKeys;
  }

  public void setPrivateKeys(PGPSecretKeyRingCollection privateKeys) {
    _privateKeys = privateKeys;
  }

  public void setPublicKeys(PGPPublicKeyRingCollection publicKeys) {
    _publicKeys = publicKeys;
  }

  public void setPassphrase(String passphrase) {
    this.passphrase = passphrase;
  }

  public PGPPrivateKey findPrivateKey(long keyID)
    throws PGPException, NoSuchProviderException {
      PGPSecretKey pgpSecKey = getPrivateKeys().getSecretKey(keyID);

      if (pgpSecKey == null)
        return null;

      return pgpSecKey.extractPrivateKey((passphrase == null ? null : passphrase.toCharArray()), "BC");
  }

  /** End Accessor Methods **/

  /**
   * Decryption Instance Methods
  **/

  public byte[] decryptBytes(byte[] encryptedBytes)
    throws IOException, PGPException, NoSuchProviderException, SignatureException, VerificationFailedException {
      InputStream stream = new ByteArrayInputStream(encryptedBytes);
      return decryptStream(stream);
  }

  public byte[] decryptStream(InputStream encryptedStream)
    throws IOException, PGPException, NoSuchProviderException, SignatureException, VerificationFailedException {

      InputStream decoderStream = PGPUtil.getDecoderStream(encryptedStream);

      PGPObjectFactory pgpF = new PGPObjectFactory(decoderStream);
      PGPEncryptedDataList encryptedData = null;
      Object encryptedObj = pgpF.nextObject();
      Iterator encryptedDataIterator;
      PGPPublicKeyEncryptedData publicKeyData = null;
      PGPPrivateKey privateKey = null;
      InputStream decryptedDataStream;
      PGPObjectFactory pgpFactory;
      PGPCompressedData compressedData;
      PGPLiteralData literallyTheRealFuckingData;
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      byte[] returnBytes;

      // the first object might be a PGP marker packet.
      if (encryptedObj instanceof PGPEncryptedDataList)
        encryptedData = (PGPEncryptedDataList) encryptedObj;
      else
        encryptedData = (PGPEncryptedDataList) pgpF.nextObject();

      encryptedDataIterator = encryptedData.getEncryptedDataObjects();

      while (privateKey == null && encryptedDataIterator.hasNext()) {
        publicKeyData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();

        privateKey = findPrivateKey(publicKeyData.getKeyID());
      }

      if (privateKey == null)
        throw new IllegalArgumentException("secret key for message not found.");

      decryptedDataStream = publicKeyData.getDataStream(privateKey, "BC");

      pgpFactory = new PGPObjectFactory(decryptedDataStream);

      compressedData = (PGPCompressedData) pgpFactory.nextObject();

      pgpFactory = new PGPObjectFactory(compressedData.getDataStream());

      PGPOnePassSignatureList opsList = null;
      PGPOnePassSignature ops = null;
      PGPPublicKey signingKey = null;
      Object obj = pgpFactory.nextObject();
      if (obj instanceof PGPOnePassSignatureList) {
        opsList = (PGPOnePassSignatureList) obj;
        ops = opsList.get(0);
        if (_publicKeys != null) {
          signingKey = _publicKeys.getPublicKey(ops.getKeyID());
          // TODO warn on key not found
        }
        // TODO warn on no public keys set
        if (signingKey != null) {
          ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingKey);
        }

        literallyTheRealFuckingData = (PGPLiteralData) pgpFactory.nextObject();
      } else if (obj instanceof PGPLiteralData) {
        literallyTheRealFuckingData = (PGPLiteralData) obj;
      } else {
        throw new RuntimeException("unexpected object");
      }

      decryptedDataStream = literallyTheRealFuckingData.getInputStream();

      int ch;
      while ((ch = decryptedDataStream.read()) >= 0) {
        if (signingKey != null) {
          ops.update((byte)ch);
        }
        outputStream.write(ch);
      }

      returnBytes = outputStream.toByteArray();
      outputStream.close();

      if (signingKey != null) {
        PGPSignatureList sigList = (PGPSignatureList) pgpFactory.nextObject();
        if (!ops.verify(sigList.get(0))) {
          throw new VerificationFailedException("Error: Signature could not be verified.");
        }
      }

      return returnBytes;
  }

}
