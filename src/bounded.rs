use core::ops::Index;
use core::ops::IndexMut;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Bounded<const N: usize>(u8);

impl<const N: usize> Bounded<N> {
    /// # Panics
    /// Panics if out-of-bounds
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn new(n: u32) -> Self {
        assert!(N <= 255);
        assert!(n < N as u32, "attempt create an illegal bounded value");
        Self(n as u8)
    }

    #[must_use]
    pub const fn get(self) -> u8 { self.0 }
}

impl<T, const N: usize> Index<Bounded<N>> for [T; N] {
    type Output = T;
    fn index(&self, idx: Bounded<N>) -> &Self::Output {
        unsafe { self.get_unchecked(idx.0 as usize) }
    }
}

impl<T, const N: usize> IndexMut<Bounded<N>> for [T; N] {
    fn index_mut(&mut self, idx: Bounded<N>) -> &mut Self::Output {
        unsafe { self.get_unchecked_mut(idx.0 as usize) }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub struct State {
        pub rf: [u64; 32],
    }

    impl State {
        pub fn add(&mut self, rd: Bounded<32>, rs1: Bounded<32>, rs2: Bounded<32>) {
            self.rf[rd] = self.rf[rs1] + self.rf[rs2];
        }
    }

    #[test]
    fn simple_use() {
        use crate::bounded::Bounded;
        let mut s = State { rf: [42; 32] };
        let r4 = Bounded::new(4);
        let r5 = Bounded::new(5);
        let r6 = Bounded::new(6);
        s.add(r4, r5, r6);
        assert_eq!(s.rf[4], 84);
    }

    #[test]
    #[should_panic = "attempt create an illegal bounded value"]
    fn will_fail() {
        let a = [42; 42];

        println!("{}", a[Bounded::new(42)]);
    }
}
