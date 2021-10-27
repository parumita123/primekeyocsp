import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.IOException;

public class OcspCheckerImpl implements OcspChecker {


    public BasicOCSPResp ocspConverter(byte[] ocspByteResponse) {
        OCSPResp ocspResponse;
        try {
            ocspResponse = new OCSPResp(ocspByteResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        BasicOCSPResp basicResponse = getBasicOCSPResp(ocspResponse);
        return basicResponse;
    }


    private BasicOCSPResp getBasicOCSPResp(OCSPResp ocspResponse) {
        BasicOCSPResp basicResponse;
        try {
            if (ocspResponse == null || ocspResponse.getStatus() != 0) {
                printLog("Invalid OCSP request");
                return null;
            }

            basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
            if (basicResponse == null) {
                printLog("Cannot extract OCSP response object. OCSP response status: " + ocspResponse.getStatus());
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return basicResponse;
    }

    public boolean verifyOcspSignature(BasicOCSPResp basicOCSPResp) {
        if (basicOCSPResp != null) {
            X509CertificateHolder[] chain = basicOCSPResp.getCerts();
            try {
                boolean verify = basicOCSPResp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(chain[0]));
                if (!verify) {
                    printLog("OCSP response signature was not valid");
                    return false;
                } else {
                    printLog("OCSP response signature is valid");
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        } else {
            return false;
        }

    }

    public boolean verifyOcspNonce(BasicOCSPResp basicOCSPResp) {
        byte[] noncerep = null;
        try {
            noncerep = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
        } catch (IOException e) {
            printLog("Failed to read extension from OCSP response. " + e.getLocalizedMessage());
        }

        if (noncerep == null) {
            printLog("Sent an OCSP request containing a nonce, but the OCSP response does not contain a nonce");
        }

        SingleResp[] singleResp = basicOCSPResp.getResponses();
        for (SingleResp resp : singleResp) {
            CertificateID respCertID = resp.getCertID();
            Object status = resp.getCertStatus();
            String statusMsg = "Status of certificate with Serial:";
            if (status == CertificateStatus.GOOD) {
                printLog(statusMsg + respCertID.getSerialNumber() + " is good");
                return true;
            } else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                printLog(statusMsg + respCertID.getSerialNumber() + " is revoked");
                return false;
            } else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
                printLog(statusMsg + respCertID.getSerialNumber() + " is unknown");
                return false;
            } else {
                printLog(statusMsg + respCertID.getSerialNumber() + " is not recognized");
                return false;
            }
        }

        return false;
    }


    private static void printLog(String log) {
        System.out.println(log);
    }
}
