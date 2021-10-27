import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import util.InputReader;

public class OcspResponseHandler {

    public static void main(String[] args) {
        InputReader fileReader = new InputReader();
        final byte[] ocspResp = fileReader.readInputBytes();
        final OcspChecker ocspChecker = new OcspCheckerImpl();
        BasicOCSPResp basicResponse = ocspChecker.ocspConverter(ocspResp);
        if (basicResponse == null) {
            return;
        }

        if (ocspChecker.verifyOcspSignature(basicResponse)) {
            ocspChecker.verifyOcspNonce(basicResponse);
        }
    }
}
