package org.jhblockchain.crypto;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jhblockchain.crypto.bip32.ExtendedKey;
import org.jhblockchain.crypto.bip39.MnemonicException.MnemonicLengthException;
import org.jhblockchain.crypto.bip44.AddressIndex;
import org.jhblockchain.crypto.bip44.BIP44;
import org.jhblockchain.crypto.bip44.CoinPairDerive;
import org.jhblockchain.crypto.exceptions.ValidationException;
import org.junit.Test;

public class Bip44Test {
	CoinPairDerive coinKeyPair;

	public Bip44Test() {
		Security.addProvider(new BouncyCastleProvider());
		ExtendedKey extendedKey = new Bip32Test().testRandomExtendedKey();
		coinKeyPair = new CoinPairDerive(extendedKey);
	}

	@Test
	public void testbip44EthereumExtendedKey() throws ValidationException {
		Log.log("testbip44EthereumExtendedKey--------->");

		AddressIndex address0 = BIP44.m().purpose44().coinType(CoinTypes.Ethereum).account(0).external().address(0);
		Log.log("address0:" + address0.toString());
		ExtendedKey key0 = coinKeyPair.deriveByExtendedKey(address0);
		AddressIndex address1 = BIP44.m().purpose44().coinType(CoinTypes.Ethereum).account(0).external().address(1);
		Log.log("address1:" + address1.toString());
		ExtendedKey key1 = coinKeyPair.deriveByExtendedKey(address1);
		Log.log(String.valueOf(key0.getParent()));
		Log.log(String.valueOf(key1.getParent()));
	}

	@Test
	public void testbip44EthereumEcKey() throws MnemonicLengthException, ValidationException {
		Log.log("testbip44EthereumEcKey--------->");

		AddressIndex address0 = BIP44.m().purpose44().coinType(CoinTypes.Ethereum).account(0).external().address(0);
		Log.log("address0:" + address0.toString());
		ECKeyPair eckey0 = coinKeyPair.derive(address0);
		Log.log("eckey0: pub=" + eckey0.getPublicKey());
		Log.log("eckey0: pri=" + eckey0.getPrivateKey());
		AddressIndex address1 = BIP44.m().purpose44().coinType(CoinTypes.Ethereum).account(0).external().address(1);
		Log.log("address1:" + address1.toString());
		ECKeyPair eckey1 = coinKeyPair.derive(address1);
		Log.log("eckey1: pub=" + eckey1.getPublicKey());
		Log.log("eckey1: pri=" + eckey1.getPrivateKey());
		
	}
}
