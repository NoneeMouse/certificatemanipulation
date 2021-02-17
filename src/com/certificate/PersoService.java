package com.certificate;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

public class PersoService {

    /** Additional APDUs needed for personalisation */
    static final byte INS_WRITEBINARY = (byte) 0xD0;

    static final byte INS_CREATEFILE = (byte) 0xE0;

    static final byte INS_PUTDATA = (byte) 0xDA;

    static final byte INS_SELECT = (byte) 0xA4;

    static final byte INS_READBINARY = (byte) 0xB0;

    /**
     * The hierarchical structure for the file system in our applet. The data is
     * as follows, concatenated in sequence:
     *
     * byte 0: -1/0 -1 for DF, 0 for EF byte 1, 2: fid msb, fid lsb byte 3:
     * index to the parent in this array, -1 of root node byte 4: for EF the SFI
     * of this file for DF number of children nodes, the list of indexes to the
     * children follow.
     *
     */
    public static final byte[] fileStructure = { -1, 0x3F, 0x00, -1, 2, 7, 12, // MF
            0, 0x2F, 0x00, 0, 0x1E, // EF.DIR
            -1, 0x50, 0x15, 0, 9, 26, 31, 36, 41, 46, 51, 56, 61, 66, // DF.CIA
            0, 0x50, 0x32, 12, 0x12, // EF.CIAInfo
            0, 0x50, 0x31, 12, 0x11, // EF.OD
            0, 0x42, 0x00, 12, 0x00, // EF.AOD
            0, 0x40, 0x00, 12, 0x00, // EF.PrKD
            0, 0x41, 0x00, 12, 0x00, // EF.CD
            0, 0x41, 0x01, 12, 0x00, // EF.Private key
            0, 0x41, 0x02, 12, 0x00, // EF.public key
            0, 0x41, 0x03, 12, 0x00, // EF.Certificate
            0, 0x41, 0x04, 12, 0x00, // EF.UserCert3
    };
    private final CardChannel channel;

    public PersoService(CardChannel channel) {
        this.channel=channel;
    }

    public void selectApplet(byte aid[]) throws CardException {
       CommandAPDU selectApplet= (new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid,0x00));
        ResponseAPDU r = channel.transmit(selectApplet);
        checkSW(r,"select applet :");
    }
    public void createFile(int fid, int length, boolean pin) throws CardException {
        byte[] data = { (byte) (fid >> 8), (byte) (fid & 0xFF),
                (byte) (length >> 8), (byte) (length & 0xFF),
                (byte) (pin ? 0x01 : 0x00) };
        CommandAPDU c = new CommandAPDU(0, INS_CREATEFILE, 0, 0, data);
                ResponseAPDU r = channel.transmit(c);
                checkSW(r,"create file :");
    }

    public  void createFileStructure() throws CardException {
    	 String hexStr = Util.byteArrayToString(fileStructure, false);
         System.out.println("File structure information: "+hexStr);
    	CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, 0x69, 0x00, fileStructure);
        ResponseAPDU r = channel.transmit(c);
        checkSW(r,"create file structure :");
    }

    public void setState(byte state) throws CardException {
        CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, 0x68, state);
        ResponseAPDU r = channel.transmit(c);
        checkSW(r,"set state :");
    }

    public void selectFile(short id) throws CardException {
        byte[] data = { (byte) (id >> 8), (byte) (id & 0xFF)};
        CommandAPDU c = new CommandAPDU(0, INS_SELECT, 0, 0, data, 256);
        ResponseAPDU r = channel.transmit(c);
        checkSW(r,"select file :");
    }

    public void writeFile(byte[] data, short dOffset, int dLen, short fOffset) throws CardException {
        ByteArrayOutputStream apduData = new ByteArrayOutputStream();
        apduData.write(data, dOffset, dLen);
        CommandAPDU c = new CommandAPDU(0, INS_WRITEBINARY,
                (byte) (fOffset >> 8), (byte) (fOffset & 0xFF), apduData
                .toByteArray());
                 ResponseAPDU r = channel.transmit(c);
                 checkSW(r,"write binary:");
    }

    public void setCertificate(int fid, X509Certificate cert, boolean pin) throws CardException {
        try {
            byte[] certBytes = cert.getEncoded();
            createFile(fid, 32767, pin);
            selectFile((short) fid);
            int blockSize = 128;
            short offset = 0;
            while (offset < certBytes.length) {
                if (offset + blockSize > certBytes.length) {
                    blockSize = certBytes.length - offset;
                }
                writeFile(certBytes, offset, blockSize, offset);
                offset += blockSize;
            }
        } catch (Exception e) {
            e.printStackTrace();
            checkSW(new ResponseAPDU(new byte[] { 0x6F, 0x00 }),
                    "setCertificate : ");
        }
    }
    
    public void writeToFile(int fid, byte[] certBytes , boolean pin) throws CardException {
        try {
            int blockSize = 128;
            short offset = 0;
            while (offset < certBytes.length) {
                if (offset + blockSize > certBytes.length) {
                    blockSize = certBytes.length - offset;
                }
                writeFile(certBytes, offset, blockSize, offset);
                offset += blockSize;
            }
        } catch (Exception e) {
            e.printStackTrace();
            checkSW(new ResponseAPDU(new byte[] { 0x6F, 0x00 }),
                    "setCertificate : ");
        }
    }

    public byte[] readFile(short offset, int len) throws CardException {
        CommandAPDU c = new CommandAPDU(0, INS_READBINARY, (byte) (offset >> 8), (byte) (offset & 0xFF), len);
        ResponseAPDU r = channel.transmit(c);
        byte[] result = r.getBytes();

        if (result[result.length - 2] == 0x62
                && result[result.length - 1] == (byte) 0x82) {
            result[result.length - 2] = (byte) 0x90;
            result[result.length - 1] = (byte) 0x00;
            r = new ResponseAPDU(result);
        }
        checkSW(r, "readFile : ");
        return r.getData();
    }

    public byte[] readFile(short id)  {
        try {
            selectFile(id);
            short offset = 0;
            int blockSize = 128;
            ByteArrayOutputStream collect = new ByteArrayOutputStream();
            while (true) {
                byte[] temp = readFile(offset, blockSize);
                collect.write(temp);
                offset += temp.length;
                if (temp.length < blockSize) {
                    break;
                }
            }
            return collect.toByteArray();
        } catch (IOException | CardException ioe) {
            ioe.printStackTrace();
            //throw new CardServiceException(ioe.getMessage());
        }
        return null;
    }
    protected void checkSW(ResponseAPDU r, String message)
            throws CardException {
        if (r.getSW() != 0x9000) {
            throw new CardException(message+" failed, status: "
                    + Util.byteArrayToString(new byte[] { (byte) r.getSW1(),
                    (byte) r.getSW2() }, false));
        }
        else {
        	System.out.println(message+ "success, status:"+ Util.byteArrayToString(new byte[] { (byte) r.getSW1(),
                    (byte) r.getSW2() },false));
        }
    }
}
