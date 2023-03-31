/**
 * Copyright (c) 2000-2012 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.license.validator;

import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.PortalClassLoaderUtil;
import com.liferay.portal.kernel.util.StringBundler;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.license.License;
import com.liferay.portal.license.LicenseConstants;

import java.security.MessageDigest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author Brian Wing Shun Chan
 * @author Amos Fong
 */
public class KeyValidator {

	public static License registerTrial(License license) {
		String licenseEntryType = license.getLicenseEntryType();

		if (!licenseEntryType.equals(LicenseConstants.TYPE_TRIAL)) {
			return license;
		}

		if (!validate(license)) {
			return license;
		}

		license.setLicenseEntryType(LicenseConstants.TYPE_DEVELOPER);

		license.setKey(_instance._encrypt(license.getProperties()));

		return license;
	}

	public static boolean validate(License license) {
		String key = _instance._encrypt(license.getProperties());

		for (String bannedKey : _BANNED_KEYS) {
			if (key.equals(bannedKey)) {
				return false;
			}
		}

		if (key.equals(license.getKey())) {
			return true;
		}
		else {
			return false;
		}
	}

	private KeyValidator() {
	}

	private String _digest(String text, String algorithm) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance(algorithm);

		messageDigest.update(text.getBytes());

		byte[] bytes = messageDigest.digest();

		StringBuilder sb = new StringBuilder(bytes.length << 1);

		for (int i = 0; i < bytes.length; i++) {
			int byte_ = bytes[i] & 0xff;

			sb.append(_HEX_CHARACTERS[byte_ >> 4]);
			sb.append(_HEX_CHARACTERS[byte_ & 0xf]);
		}

		return sb.toString();
	}

	private String _digestsToString(List<String> digests) {
		StringBundler sb = new StringBundler(digests.size());

		for (String digest : digests) {
			sb.append(digest);
		}

		return sb.toString();
	}

	private String _encrypt(Map<String, String> properties) {
		int licenseVersion = GetterUtil.getInteger(properties.get("version"));
		String productId = properties.get("productId");

		try {
			if (licenseVersion == 1) {
				throw new IllegalArgumentException(
					"Invalid version " + licenseVersion);
			}
			else if (licenseVersion >= 2) {
				return _encryptVersion2(productId, properties);
			}
		}
		catch (Exception e) {
			_log.error(e, e);
		}

		return StringPool.BLANK;
	}

	private String _encryptVersion2(
			String productId, Map<String, String> properties)
		throws Exception {

		List<String> keys = new ArrayList<>(properties.keySet());

		Collections.sort(keys);

		List<String> digests = new ArrayList<>(properties.size());

		for (int i = 0; i < keys.size(); i++) {
			String text = properties.get(keys.get(i));

			String algorithm = _getAlgorithm(productId, i);

			String digest = _digest(text, algorithm);

			digests.add(digest);
		}

		digests = _shortenDigests(digests);

		for (int i = 0; i < digests.size(); i++) {
			String digest = digests.get(i);

			String algorithm = _getAlgorithm(productId, i);

			digest = _digest(digest, algorithm);

			digests.set(i, digest);
		}

		if (_DXP &&
			(Validator.isNull(productId) ||
				productId.equals(LicenseConstants.PRODUCT_ID_PORTAL))) {

			return _interweaveDigest(digests);
		}
		else {
			return _digestsToString (digests);
		}
	}

	private String _getAlgorithm(String productId, int i) {
		if (_DXP &&
			(Validator.isNull(productId) ||
			 productId.equals(LicenseConstants.PRODUCT_ID_PORTAL))) {

			return _ALGORITHMS[i % _ALGORITHMS.length];
		}
		else {
			return _ALGORITHMS[2];
		}
	}

	private String _interweaveDigest(List<String> digests) {
		int size = digests.size();

		int finalLength = 0;
		int shortestLength = Integer.MAX_VALUE;

		for (String digest : digests) {
			int length = digest.length();

			finalLength += length;

			if (length < shortestLength) {
				shortestLength = length;
			}
		}

		StringBuilder sb = new StringBuilder(finalLength);

		for (int i = 0; i < shortestLength; i++) {
			for (int j = 0; j < size; j++) {
				String digest = digests.get(j);

				sb.append(digest.charAt(i));
			}
		}

		for (String digest : digests) {
			if (digest.length() > shortestLength) {
				sb.append(digest.substring(shortestLength));
			}
		}

		return sb.toString();
	}

	private List<String> _shortenDigests(List<String> digests)
		throws Exception {

		int size = digests.size();

		int groupSize = size / 4;

		if ((groupSize * 4) < size) {
			groupSize++;
		}

		List<String> shortenedDigests = new ArrayList<>(4);

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < size; i++) {
			String digest = digests.get(i);

			if ((i != 0) && ((i % groupSize) == 0)) {
				shortenedDigests.add(sb.toString());

				sb.setLength(0);
			}

			sb.append(digest);
		}

		if (shortenedDigests.size() < 4) {
			shortenedDigests.add(sb.toString());
		}

		return shortenedDigests;
	}

	private static final String[] _ALGORITHMS = {
		"MD5", "SHA-1", "SHA-256", "SHA-512"
	};

	private static final String[] _BANNED_KEYS = {
		"4a4beb2b97c151cff83cbca7096325086817360a7b8c912b66e1d1dea172033a8c59" +
		"34cbbacbf7b443496cc119a6a482fc6225d28bcbcb2384f52862e6fd35e49a2625f1" +
		"458d24a1f62e71235dc16b9de5a971e638af32a9784e566f33dd90234d89e1dde83e" +
		"8a4a100a70d999b2bb7fa77eeb34fd1be9cdf3645f9478b14c2cd6b8f955",
		"54538af2d017334262c28dab47f3ce9103f7aa67417b056fead163cffb140ee347c0" +
		"cb02fc21ac60b32a2db70d3c4dc9977330a750dfd0849d80c5a7450cb6baa0a23907" +
		"084a5e233740003a69ff5d6a4d3d57fe481808e91745f48c3ea03e9694a40e36ae05" +
		"3bd48aaf7c466a46204dede8728f0b1d1349f3471ad61157f205d9296e4a",
		"5bc38e22d0f733d266128c8b4fb3ca710297ac974a3b00ffe881655ffa2403e34f00" +
		"cb82fc11a070b7ba28a704bc49f99d233c0756bfdb949be0c317459cb54a61ebbf9b" +
		"e6df549e0e4ab339b9c2ec04753fe286481808e91745f48c3ea03e9694a40e36ae05" +
		"3bd48aaf7c466a46204dede8728f0b1d1349f3471ad61157f205d9296e4a",
		"8752c326d933270696b107c04a670b340b9b39c5a36197ec5a3eef29dc59ffff63bb" +
		"a5bf0d76b491c7d54ac92af864c551ccbdcb8165c70f22c2914d0790f999b3376547" +
		"fe5412150c8f075306aada3973164af9a5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"bef20ec68783cc46c9d103a048776904783be005ea51505ccf9e2d39b459ebff27fb" +
		"ccdf48b60921ab455509fff8a015ffdc8f1b6e35acbfb5f2698d0020b13948818c29" +
		"739556fcc16c82dc66f72cfb1be8bf2fa5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"4592ceb62833cb066361c61006272184e98bee45da11419c4c8e3a2974998c2fb9ab" +
		"231f7be6d1d1519530d9d7b86465011ca73b5f0526ff95b28c3d38407f89bcc046d9" +
		"a4f0758a6af81fa2f8bc93e7da2dfa40a5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"49a2c5e62d23c3766191c6b0020728d4ed6befe5d961402c4d1e3b7974d9888fb2db" +
		"254f7ef6def15c253799dd586135006cabfb5a1526cf91028b1d3e207e790816230c" +
		"e47f376b181d7c53043ef67d39b2c6e0a5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"ff1207f691639076db6195b0387744e423ab9be5dfe1bd1c10cedb0919d97dcf1f0b" +
		"1b9fd816a5c17ca5db59daa875e5504c4a2b4115111fc142d94d02d0edb91bb35f31" +
		"8625cc5f24d25b0844752418ee1537cca5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"482258863b23ac96baf16810efb7925423fb0d5528c1a21ccc0e91b9cf09d97f556b" +
		"557f5e967b51000580895138efb5ca3ca3cbcb950b2fb3a2527ddc4093b90ff5bec8" +
		"06f3d1dd07d0925dde2cde63796d3132a5a29b5524d72aa790e0d859f54c5c6b39f6" +
		"6c3b1461b11f4cf1f7b7f5e16e27a070fba8547a74cbbd92fb2d82cda1ee",
		"b0793ae49805cb2d8063bbc163410668925d87378bc493d43a464b147c025498b727" +
		"32c4bf9f36c56f632cd9b513b175c22f3f0ae17ff0ac60df082e0cecc5113bb33e28" +
		"d44fcab97d47ddc83f3a1df90e6a7eba5b8d8d77ffa12dbf8d024a9a66e4e9b77de4" +
		"6336fd644f852e53f9b2c94826fd9b3bbb4d1bc19ee44a881a470850cd16",
		"40676ad778095b6770313b300309862d0210c7ce9bdac3ff4a979bf5cc78b47e873b" +
		"325f5f30a656bf674c4835c851fa621f8fca11c4c0025010f88d6c76c5643bb33e28" +
		"dfaa24f09d30e67694ddaa0e07965de9e105f1fe29941967c2b35e177ab838e7c152" +
		"26489668ba36535422dc62688b7a018f620c5809bc526a1169db99f6617b",
		"504c5a83488fcb6e802ffb14b3bfc6c042ea37cf4bb923485af6bb9dacf9a432f7b5" +
		"92446f7b26d29f000ca515aa71ecf2fc8f53d19fd015207b582d7cddb55f3bb33e28" +
		"7270a4ecb52e5d50da0b74c929abdbfe8558b4ec2a80aa70d6eae198811d256cfcde" +
		"04a1d1b3ff0ca7ee15c03b149518d986c2d7f8e56ec7625e448ed0005e24",
		"c013caebc8d47bbb20b5cb8713e926eb52abf72efb7a33486ace2b358c11d414a741" +
		"f2ffff15f60d4fea0cec05a2c1e4e2adef88c104103b60e2c895ac8bb56d3bb33e28" +
		"09bd309754eeed839ed1d8dcd3e78c54ce7b7515057f4c1b87e1694d82542ecf30d5" +
		"50f3031cdcb7159078977ddaf0025487e94488a180c184c80ec28751e2d1",
		"d913379f68b378206ce6dca08bb48be265b7b461ebe8fbe26f9046e258e5264dbc3d" +
		"b4f1ed631a430f048b0e92f53402264458bf8540f2477fd500b9e6ca4d1df24addf7" +
		"faeaa7007a236b2d66f99c02b4df1c8e36e4d5b5476fdebc7a2a9ce03723a8fd7858" +
		"bd6faeffd785688468ff87f68f19d38b7b72caf42a7cedbb598a02ef55f0",
		"0ab084018b8db2f855303af893cb5d2be7f168f46447715c57027100bd9a5a484dc9" +
		"b72f6eec0db4ecf2ddaead15e9b1181bcd2e8367ecc49990ab596b28002fc985ad4d" +
		"24184000804d74679dbfd3e5721b05275a3272e97513670623334840d4a1af323a54" +
		"2e6c2566d2d136644f4a725c372e33de2e266f6c553747f52a95975913ce",
		"b46bba2e9047536af2195d82e7117ef9d3d7fa50215c6568ead013aa7b3ade5b67b3" +
		"7b222cfe4c1d235badd4fd6e4d849795e0aea01ec0266d0305cf25d85623a0a23907" +
		"caff72dee91c287d9b180778f8ff0f16268ec2fa91cb06f268c91c223c002bcec997" +
		"147178fd2d41ffa3201d6a5be72763d941779ba5a96ebc54ed246c8cb7a0",
		"3a02e4a0eb681217d5c4ca2b835c7d6f2709087304f9c14f47f051948da60a27bdab" +
		"17253e26bd20dc554d2fad3f19ba4834dd3793a53c82c9893bc1fb8d509cc985ad4d" +
		"5428cb1e670d36a4f7bfd888c5eed16ee992afa29d2e0068d2309f3c96fa9477d0ee" +
		"13af0fd06b8fb6f15c65a438858241f2f10aaced934e37d530d0da5e3a0c",
		"4b7ffe4fb027a3177693eca63f630a2ef2e89c254ad4c0f6d8fc6560ba9783caaf66" +
		"aba9bc3fe02b17b49832341249a78d280c558613bbce7ba8e3f6d5a9258161ebbf9b" +
		"3dc60bf1e1415d6796c05750717f410b0fe3b4b639b57a1d3a0948458730820eef72" +
		"22cba346d242f28eafe08dd665ca15a27108b89e218695e349fe02e3a38f",
		"442ffa1fb097a3377293eda637a30e7ef3e89ab541b4c5d6da8c6390bbb78eaaa7d6" +
		"abc9bc0fecab13049da23de24d478758008580c3b0ae7de8e5f6d5192681a0a23907" +
		"3d0f3ba603147eab1ebff185058c881e0fe3b4b639b57a1d3a0948458730820eef72" +
		"22cba346d242f28eafe08dd665ca15a27108b89e218695e349fe02e3a38f",
		"cb03be22e089038d86dd4c865f945a8e42ad3c24fafef07fc8e775fb8a75932bbfc6" +
		"5b274c7ac0a7e79288d2b4e27985edcc2cf756927bee8b932390e590c5e061ebbf9b" +
		"ecf3ce0b3e51b2b338d4ba94284145a01fe5552705a04f0389946da5f1770b406248" +
		"054a41dd58f49ac17683de4bfd672d497ce84fd94400f17d41efbe78f8f6",
		"c433ba82e099032d821d4d9657345e0e431d3af4f1cef57fcaa773cb8bc59e9bb7c6" +
		"5b974c6acc87e3128d62bde27d45e74c20e75072701e8d932520e5e0c600a0a23907" +
		"7ecd97cb4e185fd65ae08dc9829d4ed51fe5552705a04f0389946da5f1770b406248" +
		"054a41dd58f49ac17683de4bfd672d497ce84fd94400f17d41efbe78f8f6"
	};

	private static final char[] _HEX_CHARACTERS = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
		'e', 'f'
	};

	private static Log _log = LogFactoryUtil.getLog(KeyValidator.class);

	private static KeyValidator _instance = new KeyValidator();

	private static final boolean _DXP;

	static {
		ClassLoader classLoader = PortalClassLoaderUtil.getClassLoader();

		boolean dxp = false;

		try {
			classLoader.loadClass(
				"com.liferay.portal.ee.license.LCSLicenseManager");

			dxp = true;
		}
		catch (ReflectiveOperationException reflectiveOperationException) {
		}

		_DXP = dxp;
	}

}