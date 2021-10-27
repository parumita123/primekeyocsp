import org.bouncycastle.cert.ocsp.BasicOCSPResp;

public interface OcspChecker {
    BasicOCSPResp ocspConverter(byte[] bytes);

    boolean verifyOcspSignature(BasicOCSPResp basicOCSPResp);

    boolean verifyOcspNonce(BasicOCSPResp basicOCSPResp);
}
