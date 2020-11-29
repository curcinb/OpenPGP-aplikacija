package etf.openpgp.cb160549;


public class RezultatDekripcije {
        /**
         * Polja koja opisuju rezultat dekripcije
         */
        private String decryptFileName = "";
        private boolean isSigned = false;
        private PPGPPJavniKljuc signee = null;
        private boolean isSignatureValid = false;
        private Exception signatureException = null;
        private String decryptedText;

        public String getDecryptFileName() {
            return decryptFileName;
        }

        public void setDecryptFileName(String decryptFileName) {
            this.decryptFileName = decryptFileName;
        }

        public boolean isIsSigned() {
            return isSigned;
        }

        public void setIsSigned(boolean isSigned) {
            this.isSigned = isSigned;
        }

        public PPGPPJavniKljuc getSignee() {
            return signee;
        }

        public void setSignee(PPGPPJavniKljuc signee) {
            this.signee = signee;
        }

    public boolean isIsSignatureValid() {
        return isSignatureValid;
    }

    public void setIsSignatureValid(boolean isSignatureValid) {
        this.isSignatureValid = isSignatureValid;
    }

    public Exception getSignatureException() {
        return signatureException;
    }

    public void setSignatureException(Exception signatureException) {
        this.signatureException = signatureException;
    }

    public String getDecryptedText() {
        return decryptedText;
    }

    public void setDecryptedText(String decryptedText) {
        this.decryptedText = decryptedText;
    }
    }
