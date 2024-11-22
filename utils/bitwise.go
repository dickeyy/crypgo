package bitwise

func RightRotate(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func Ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func Maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func Sigma0(x uint32) uint32 {
	return RightRotate(x, 2) ^ RightRotate(x, 13) ^ RightRotate(x, 22)
}

func Sigma1(x uint32) uint32 {
	return RightRotate(x, 6) ^ RightRotate(x, 11) ^ RightRotate(x, 25)
}
