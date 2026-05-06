#![doc = include_str!("../README.md")]

#[expect(
    clippy::print_stdout,
    reason = "It's a hello world, what do you think clippy?!"
)]
fn main() {
    println!("Hello, world!");
}
