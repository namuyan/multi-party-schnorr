
#[cfg(test)]
mod test {
    use crate::python::utils::*;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{BigInt, FE, GE};

    #[test]
    fn ecdhe() {
        let ec_point0: GE = ECPoint::generator();
        let secret0: FE = ECScalar::new_random();
        let public0: GE = ec_point0.scalar_mul(&secret0.get_element());
        let ec_point1: GE = ECPoint::generator();
        let secret1: FE = ECScalar::new_random();
        let public1: GE = ec_point1.scalar_mul(&secret1.get_element());
        assert_ne!(secret0, secret1);
        assert_ne!(public0, public1);
        let mux01 = public0.scalar_mul(&secret1.get_element());
        let mux10 = public1.scalar_mul(&secret0.get_element());
        assert_eq!(mux01.pk_to_key_slice(), mux10.pk_to_key_slice());
        let byte = public0.get_element().serialize();
        println!("{:?}", byte[0]);
        println!("x0:{:?}", public0.x_coor().unwrap());
        println!("y0:{:?}", public0.y_coor().unwrap());
        let public2: GE = bytes2point(&byte).expect("Why?");
        println!("x2:{:?}", public2.x_coor().unwrap());
        println!("y2:{:?}", public2.y_coor().unwrap());
        assert_eq!(public0, public2);
    }

    #[test]
    fn add_point() {
        let a0 = GE::random_point();
        let a1 = GE::random_point();
        let r_direct = a0.add_point(&a1.get_element());
        let mut g = GE::generator();
        g = a0 + g;
        g = a1 + g;
        g = g.sub_point(&GE::generator().get_element());
        assert_eq!(r_direct, g);
    }
}
