/**
 * @file  LoyaltyCardApplet.java
 * @Loyalty Card Applet Sample Code
 * @copyright Copyright(C) 2016 JavaCardOS Technologies Co., Ltd. All rights reserved.
 * www.javacardos.com
 */

package LoyaltyCardApplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class LoyaltyCardApplet extends Applet
{
	private final static byte Loyalty_CLA =(byte)0x80; 
   
    private final static byte INS_ISSUE_CARD = (byte)0x10;
    private final static byte INS_VERIFY = (byte)0x20;
    private final static byte INS_UPDATE_PIN = (byte)0x24;
    private final static byte INS_CREDIT = (byte)0x30;
    private final static byte INS_PURCHASE = (byte)0x40;
    private final static byte INS_GET_BALANCE = (byte)0x50;
    private final static byte INS_GET_POINTS =(byte)0x51;
    private final static byte INS_GET_CARDID= (byte)0x70;
    private final static byte INS_EXTERNAL_AUTH = (byte)0x82;
    private final static byte INS_GET_CHANNEL = (byte)0x84;
    private final static byte INS_INTERNAL_AUTH = (byte)0x88;
    
    private final static  byte MAX_NUM_CARDID = 8;
    // maximum balance
    private final static short MAX_BALANCE = (short)0x7fff;
    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    // signal the the INTEGRAL becomes negative
    final static short SW_EXCEED_MAXIMUM_INTEGRAL = 0x6A83;
    
    final static short SW_EXTERAL_MARK = 0x6A86;

    private final static byte balance_new[] = {0x00, 0x00};
    private final static byte MaxIntegral[] = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
    private final static byte Integral_new[] = {0x00, 0x00, 0x00, 0x00}; 
     
	short balance;
	short integral;
	//the mark of whether to generate random data in External Authentication process
	boolean bRand;
	//the mark of whether to perform External Authentication
	boolean ExternalMark;
    byte[] cardID;
	byte[] output;
	OwnerPIN userPin;
	DESKey Key;
	Cipher desCipher;
	RandomData myRandomS;
	
	//the maximum number of times an incorrect PIN can be presented.
    final static byte PIN_TRY_LIMIT = (byte)0x03;
    //the maximum allowed PIN size.
    final static byte MAX_PIN_SIZE = (byte)0x08;
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	//the algorithm related initialization values
	final static byte[] seed = {(byte)0x58, (byte)0x49, (byte)0x72, (byte)0x15, (byte)0x3E, (byte)0xA7, (byte)0xB0, (byte)0xC8};	
	final static byte[] input = {(byte)0xC8, (byte)0xA2, 0x35, (byte)0x5E, 0x0F, 0x1B, (byte)0x86, (byte)0xE2};
	final static byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
    private LoyaltyCardApplet(byte bArray[], short bOffset, byte bLength)
    {
    	balance = 0;
    	integral = 0;
    	Key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);    		
    	desCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);
		myRandomS = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        userPin = new OwnerPIN(PIN_TRY_LIMIT,   MAX_PIN_SIZE);
        cardID = new byte[MAX_NUM_CARDID];  
//        Util.arrayFillNonAtomic(cardID, (short)0, (short)8, (byte)0x11);
        output = new byte[16];
        bRand = false;
        ExternalMark = false;
        register();	
    }
    public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new LoyaltyCardApplet(bArray, bOffset, bLength);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		
		if ((buf[ISO7816.OFFSET_CLA] == Loyalty_CLA) ||
	        (buf[ISO7816.OFFSET_CLA] == ISO7816.CLA_ISO7816))
		{
		    switch (buf[ISO7816.OFFSET_INS]) 
		    {
				case INS_ISSUE_CARD:
					IssueCard(apdu);
					return;
	        	case INS_CREDIT:
	        		Credit(apdu);
	        		return;   
	        	case INS_VERIFY:
	        		Verify(apdu);
	        		return;	        		
	        	case INS_PURCHASE :
	        		Purchase(apdu);
	        		return;
	        	case INS_GET_BALANCE:
	        		GetBalance(apdu);
	        		return;	        		
	        	case INS_GET_POINTS:
	        		GetPoints(apdu);	        		
	        		return;
	        	case INS_GET_CARDID: 
	        	    GetCardID(apdu);
	        	    return;
				case INS_UPDATE_PIN:
					UpdatePin(apdu);
					return;
	    		case INS_GET_CHANNEL:
	    			GetChannel(apdu);
	    			return;
	    		case INS_EXTERNAL_AUTH:
					ExternalAuth(apdu);
	    			return;
	    		case INS_INTERNAL_AUTH:
	    			InternalAuth(apdu);
	    			return;   		
		    	default:
		    		bRand = false;
		    		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		    }
		} else {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
	
	//In issue card process, there contains a PIN, key and the card ID
	private void IssueCard(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();
		if (dataLen != (3 + MAX_PIN_SIZE + ((short) (KeyBuilder.LENGTH_DES3_2KEY & 0xFF) >> 3) + MAX_NUM_CARDID)) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		short offset = ISO7816.OFFSET_CDATA;    
        byte pinLen = buffer[offset];
        if (pinLen != MAX_PIN_SIZE) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // The input data contain the PIN initialization value
        userPin.update(buffer, (short)(offset+1), pinLen);
        
        // Initialize key
        offset = (short)(offset+pinLen+1);
        byte keyLen = buffer[offset];
        if (keyLen != (KeyBuilder.LENGTH_DES3_2KEY >> 3)) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Key.setKey(buffer, (short)(offset+1));
        
        // Initialize cardID
        offset = (short)(offset+keyLen+1);
        byte idLen = buffer[offset];
        if (idLen != MAX_NUM_CARDID) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        Util.arrayCopy(buffer, (short)(offset+1), cardID, (short)0, (short)idLen); 
	}
	
	//old PIN + new PIN
	private void UpdatePin(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short offset = ISO7816.OFFSET_CDATA;
        // retrieve the PIN data for validation.
        short recvLen = apdu.setIncomingAndReceive(); 
        if (recvLen != 0x12) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        byte pinLen = buffer[offset]; 
        if (pinLen != 8) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (userPin.check(buffer, (short)(offset+1), pinLen) == false)
        {
	        ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        offset = (short)(offset+pinLen+1);
        pinLen = buffer[offset];
        if (pinLen != 8) {
	        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // update pin
        userPin.update(buffer, (short)(offset+1), pinLen);
	}
	
	private short calculateCryptogram(DESKey key, byte[] input, short sin, short inLen, byte[] output, short sou)
	{
		short ouLen;
		desCipher.init(key, Cipher.MODE_ENCRYPT, iv, (short)0, (short)8);
        ouLen = desCipher.doFinal(input, (short)sin, (short)inLen, output, (short)sou);
		return ouLen;
	}  
	
     
    private void Verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead =(byte)(apdu.setIncomingAndReceive());

		// the PIN data is read into the APDU buffer at the offset ISO7816.OFFSET_CDATA, the PIN data length = byteRead
		if (userPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false)
		{
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
    }
    private void GetBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();  
        short le = apdu.setOutgoing();	        
        apdu.setOutgoingLength((byte)2);   
        apdu.sendBytesLong(balance_new, (short)0, (short)2);
    } 
    
    private void GetPoints(APDU apdu) 
    {
    	byte[] buffer = apdu.getBuffer();  
        short le = apdu.setOutgoing();	        
        apdu.setOutgoingLength((byte)4);   
        apdu.sendBytesLong(Integral_new, (short)0, (short)4);
    }
    private void GetCardID(APDU apdu)
    {
        short le = apdu.setOutgoing();
        apdu.setOutgoingLength(MAX_NUM_CARDID);
        apdu.sendBytesLong(cardID,(short)0, (short)MAX_NUM_CARDID);
    }
    private void Credit(APDU apdu) {
        
	    // access authentication
        // if(!ExternalMark)
        	// ISOException.throwIt(SW_EXTERAL_MARK);
        // if (!userPin.isValidated( ))
            // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);	    
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = (short)buffer[ISO7816.OFFSET_LC];
	    short byteRead =(short)(apdu.setIncomingAndReceive());
	    
	    if (numBytes != byteRead)
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the credit amount
	    short low  = 0,high = 0;
	    byte tmpBalance[] = {0x00, 0x00};
	    if ((short)(buffer[ISO7816.OFFSET_CDATA] & 0xff) == 0 && (short)(buffer[ISO7816.OFFSET_CDATA+1] & 0xff) == 0) //consume amount is 0
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);//credit amount is 0
    
        Util.arrayCopy(balance_new, (short)(0), tmpBalance, (short)0, (short)2);  
	    
	    low=(short)(buffer[ISO7816.OFFSET_CDATA+1] & 0xff);
	    low=(short)(low + (tmpBalance[1] & 0xff));
        byte tmp = (byte)(low >> 8);
        tmpBalance[1] = (byte)(low & 0xff);
        
        high = (short)(buffer[ISO7816.OFFSET_CDATA] & 0xff);
        high = (short)(high + tmp + (tmpBalance[0] & 0xff));
        tmp = (byte)(high >> 8);
        tmpBalance[0] = (byte)(high & 0xff); 
        
        if(tmp > 0)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if((short)(tmpBalance[0]&0xff) > (short)0xff)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
    	Util.arrayCopy(tmpBalance,(short)0,balance_new,(short)0,(short)2);        
    } // end of deposit method
    
    private void Purchase(APDU apdu) {        
        if (!userPin.isValidated())
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = (short)buffer[ISO7816.OFFSET_LC];
	    short byteRead = (short)(apdu.setIncomingAndReceive());
	    
	    if (numBytes != byteRead)
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the consume amount	
	    byte temp[] = {0x00,0x00};
	    Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA), temp, (short)0, (short)2);
	    if ((short)(temp[0] & 0xff) == 0 && (short)(temp[1] & 0xff) == 0) //consume amount is 0
	    	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    if((short)(balance_new[0] & 0xff) < (short)(temp[0] & 0xff)) 
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);
	    if ((short)(balance_new[0] & 0xff) == (short)(temp[0] & 0xff) && ((short)(balance_new[1] & 0xff) < (short)(temp[1] & 0xff)))
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);
	    short low = 0, high = 0;	    
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA), temp, (short)0, (short)2);
        calIntegral(buffer, ISO7816.OFFSET_CDATA, numBytes);
        
	    low = (short)(balance_new[1] & 0xff);
	    high = (short)(balance_new[0] & 0xff);
	    if (low < (short)(temp[1] & 0xff))
	    {
	    	high = (short)(high - 1);
	    	low = (short)(low + 0x0100 - temp[1] & 0xff);
	    	temp[1] = (byte)(low & 0xff);	    	
	    }
	    else
	    {
	    	low = (short)(low - temp[1] & 0xff);
	    	temp[1] = (byte)(low & 0xff);	    	
	    }
	    
	    high = (short)(high - temp[0]);
        temp[0] = (byte)(high & 0xff);
        Util.arrayCopy(temp, (short)(0), balance_new, (short)0, (short)2);       
    }
    
    private void calIntegral(byte [] buf,byte soff,short len)
    {
    	byte tmpIntegral[] = {0x00, 0x00, 0x00, 0x00};
    	short low = 0;
    	byte tmp = 0;
        if (len == 2)
  	        Util.arrayCopy(buf, soff, tmpIntegral,(short)2, len);
        else
        	Util.arrayCopy(buf, soff, tmpIntegral,(short)0, len);
        for(short i=3; i>=0; i--)
        {
		    low = (short)(Integral_new[i] & 0xff);
		    low = (short)(low + tmp + (tmpIntegral[i]& 0xff));
	        tmp = (byte)(low >> 8);
	        tmpIntegral[i] = (byte)(low & 0xff);       	
        }
        if(tmp > 0)
        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);

        if((short)(MaxIntegral[0]&0xff)<(short)(tmpIntegral[0]&0xff))
        {
	        ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);	
        }       	
        else if((short)(MaxIntegral[0]&0xff)==(short)(tmpIntegral[0]&0xff))
        {
 	        if((short)(MaxIntegral[1]&0xff)<(short)(tmpIntegral[1]&0xff))
 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);
 	        else if((short)(MaxIntegral[1]&0xff)==(short)(tmpIntegral[1]&0xff))
 	        {
	 	        if((short)(MaxIntegral[2]&0xff)<(short)(tmpIntegral[2]&0xff))
	 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL); 
	 	        else if ((short)(MaxIntegral[2]&0xff)==(short)(tmpIntegral[2]&0xff))
	 	        {
	 	        	if((short)(MaxIntegral[3]&0xff)<(short)(tmpIntegral[3]&0xff))
		 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL); 	
	 	        }		 	        	
 	        }
        }      
    	Util.arrayCopy(tmpIntegral, (short)0, Integral_new, (short)0, (short)4);
    }
    
    private void GetChannel(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		//apdu.setIncomingAndReceive();
		if(buf[ISO7816.OFFSET_CLA] != (byte)0x00)
	    {
	    	ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	    }
	    		
	    if(buf[ISO7816.OFFSET_P1] != (byte)0x00 || buf[ISO7816.OFFSET_P2] != (byte)0x00)
	    {
	    	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	    }
	    		
	    if(buf[ISO7816.OFFSET_LC] > (byte)0x08)
	    {
	    	ISOException.throwIt(Util.makeShort((byte)0x6C, (byte)0x08));
	    }
	    			
	    short responseLength = Util.makeShort((byte)0x00, (byte)buf[ISO7816.OFFSET_LC]);
	    		
	    // Secure Random	    			
	    myRandomS.setSeed(seed, (short)0, (short)0x08);
	    myRandomS.generateData(buf, (short)ISO7816.OFFSET_CDATA, responseLength);
    			
	    Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, input, (short)0, responseLength);
	    apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, responseLength);
	    bRand = true;
	}
	
	private void ExternalAuth(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		if(bRand == false)
	    {
	    	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    }
	    bRand = false;
	    			
	    if(buf[ISO7816.OFFSET_LC] != (byte)0x08)
	    {
	    	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    }
	    short ouLen = calculateCryptogram(Key, input, (short)0, (short)8, output, (short)0);
	    if(Util.arrayCompare(buf, (short)ISO7816.OFFSET_CDATA, output, (short)0, (short)8) != 0)
	    {
	    	ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	    }
	    ExternalMark=true;
	}
	
	private void InternalAuth(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		bRand = false;
	    if(buf[ISO7816.OFFSET_LC] != (byte)0x08)
	    {
	    	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    }			
	    short ouLen = calculateCryptogram(Key, buf, (short)ISO7816.OFFSET_CDATA, (short)8, buf, (short)ISO7816.OFFSET_CDATA);
	    apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, ouLen);
	}

}
