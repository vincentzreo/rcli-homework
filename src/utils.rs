use std::{fs::File, io::Read};

pub fn get_reader(input: &str) -> anyhow::Result<Box<dyn Read>> {
    let reader = if input == "-" {
        Box::new(std::io::stdin()) as Box<dyn Read>
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}
