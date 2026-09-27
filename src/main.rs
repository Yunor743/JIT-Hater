mod checker;
mod dog;

fn main() {
    let samename1 = String::from("Helloworld");
    let samename2 = &samename1;
    let scooby = dog::Dog::new("scooby");
    let sam = dog::Dog::new(samename2);
    dog::Dog::new("hello");
    sam.bark();
    scooby.bark();
    println!("Hello, world!");
    println!("Hello dad");
    println!("Hello mom");
}
