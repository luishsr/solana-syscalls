fn main() {
    const SYS_HASH: usize = sys_hash("sol_log_");
    println!("Syscall ID for sol_log_: {}", SYS_HASH);
}

pub const fn sys_hash(name: &str) -> usize {
    murmur3_32(name.as_bytes(), 0) as usize
}

const fn murmur3_32(buf: &[u8], seed: u32) -> u32 {
    const fn pre_mix(buf: [u8; 4]) -> u32 {
        u32::from_le_bytes(buf)
            .wrapping_mul(0xcc9e2d51)
            .rotate_left(15)
            .wrapping_mul(0x1b873593)
    }

    let mut hash = seed;
    let mut i = 0;

    while i < buf.len() / 4 {
        let chunk = [buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]];
        hash ^= pre_mix(chunk);
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);
        i += 1;
    }

    // Process remaining bytes directly without mutable slice
    let remainder = match buf.len() % 4 {
        1 => [buf[i * 4], 0, 0, 0],
        2 => [buf[i * 4], buf[i * 4 + 1], 0, 0],
        3 => [buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], 0],
        _ => [0, 0, 0, 0],
    };

    if buf.len() % 4 != 0 {
        hash ^= pre_mix(remainder);
    }

    hash ^= buf.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash
}
