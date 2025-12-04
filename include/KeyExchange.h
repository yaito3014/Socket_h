#pragma once
#include "Cryptgraphy/ECDSA.h"
#include "Packet.h"

class KeyFactoryDH {
public:

	using baseint_t = bigint<32>;
	using int_t = bigint<baseint_t::Words * 2>;
	using modint_t = ModInt<int_t>;

	static inline const modint_t::Factory xmodp = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
	static inline const modint_t X = xmodp.Make("80000001F000000F80000001F0000001");
	static inline RandomGenerator rg{};

	KeyFactoryDH() {
		do {
			SecretKey = int_t(rg.NextBytes(baseint_t::WordBytes));
		} while (SecretKey >= X.GetP() || SecretKey <= 2);
	}

	[[nodiscard]]
	Cryptgraphy::bytearray GeneratePublicKey() const {
		auto&& pub = (baseint_t)X.Pow(SecretKey).value;
		
		Cryptgraphy::bytearray ret;
		ret.reserve(baseint_t::WordBytes);

		Packet::StoreBytes(ret, pub.words());

		return ret;
	}

	[[nodiscard]]
	Cryptgraphy::bytearray MakeSharedKey(const Cryptgraphy::bytearray& fromQ) const {
		baseint_t temp;
		Cryptgraphy::byte_view view(fromQ);

		Packet::LoadBytes(view, temp.words());
		modint_t Q = xmodp(temp);

		auto&& equalQ = (baseint_t)Q.Pow(SecretKey).value;

		Cryptgraphy::bytearray ret;
		ret.reserve(baseint_t::WordBytes);

		Packet::StoreBytes(ret, equalQ.words());

		return ret;
	}

	int_t SecretKey = 0;
};

#if 0

class KeyFactoryECDH {
public:

	using baseint_t = bigint<4>;
	using int_t = bigint<baseint_t::Words * 2 + 1>;
	using modint_t = ModInt<int_t>;
	using afinpoint_t = ECAfinPoint<modint_t>;

	static inline const modint_t::Factory xmodp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
	static inline const afinpoint_t::Factory pointfactory =
		WeierstrassParameter<modint_t>(
			xmodp("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
			xmodp("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
		);
	static inline const afinpoint_t G = pointfactory(
		xmodp("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		xmodp("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	);
	
	static inline RandomGenerator rg{};

	KeyFactoryECDH() {
		do {
			SecretKey = int_t(rg.NextBytes(baseint_t::WordBytes));
		} while (SecretKey >= xmodp.P() || SecretKey <= 1);
	}

	[[nodiscard]]
	Cryptgraphy::bytearray GeneratePublicKey() const {
		auto&& pubpoint = G.Scaler(xmodp(SecretKey));

		auto&& [x, y] = std::tuple{(baseint_t)pubpoint.x.value, (baseint_t)pubpoint.y.value};
		
		Cryptgraphy::bytearray ret;

		ret.reserve(baseint_t::WordBytes);
		
		Packet::StoreBytes(ret, x.words());
		
		return ret;
	}

	[[nodiscard]]
	Cryptgraphy::bytearray MakeSharedKey(const Cryptgraphy::bytearray& fromQ) const {
		baseint_t temp;
		Cryptgraphy::byte_view view(fromQ);
		
		Packet::LoadBytes(view, temp.words());
		
		afinpoint_t Q = pointfactory(
			xmodp(temp),
			G.GetParam().GetY(xmodp(temp)).Sqrt()
		);

		auto&& equalQ = Q.Scaler(xmodp(SecretKey));
		auto [x, y] = std::tuple{(baseint_t)equalQ.x.value, (baseint_t)equalQ.y.value};

		Cryptgraphy::bytearray ret;

		ret.reserve(baseint_t::WordBytes);

		Packet::StoreBytes(ret, x.words());

		return ret;
	}

	int_t SecretKey = 0;
};

#endif

class KeyFactoryECDH {
public:

	using baseint_t = bigint<4>;
	using int_t = bigint<baseint_t::Words * 2 + 1>;
	using modint_t = ModInt<int_t>;
	using afinpoint_t = ECAfinPoint<modint_t>;
	using project_t = ECProject<modint_t>;

	static inline const modint_t::Factory xmodp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
	static inline const auto param = WeierstrassParameter<modint_t>(
		xmodp("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
		xmodp("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	);
	static inline const afinpoint_t::Factory afinpoint = param;
	static inline const project_t::Factory project = param;
	static inline const afinpoint_t G = afinpoint(
		xmodp("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		xmodp("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	);

	static inline RandomGenerator rg{};

	KeyFactoryECDH() {
		do {
			SecretKey = int_t(rg.NextBytes(baseint_t::WordBytes));
		} while (SecretKey >= xmodp.P() || SecretKey <= 1);
	}

	[[nodiscard]]
	Cryptgraphy::bytearray GeneratePublicKey() const {
		auto&& pubpoint = project_t(G).Scaler(xmodp(SecretKey));

		auto&& x = (baseint_t)pubpoint.ToAfinPoint().x.value;

		Cryptgraphy::bytearray ret;

		ret.reserve(baseint_t::WordBytes);

		Packet::StoreBytes(ret, x.words());

		return ret;
	}

	[[nodiscard]]
	Cryptgraphy::bytearray MakeSharedKey(const Cryptgraphy::bytearray& fromQ) const {
		baseint_t temp;
		Cryptgraphy::byte_view view(fromQ);

		Packet::LoadBytes(view, temp.words());

		afinpoint_t Q = afinpoint(
			xmodp(temp),
			G.GetParam().GetY(xmodp(temp)).Sqrt()
		);

		auto&& equalQ = project_t(Q).Scaler(xmodp(SecretKey));
		auto x = (baseint_t)equalQ.ToAfinPoint().x.value;

		Cryptgraphy::bytearray ret;

		ret.reserve(baseint_t::WordBytes);

		Packet::StoreBytes(ret, x.words());

		return ret;
	}

	int_t SecretKey = 0;
};