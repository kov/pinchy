#![allow(unused)]
use std::pin::Pin;

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use pinchy_common::syscalls::syscall_name_from_nr;
use tokio::io::{AsyncWrite, AsyncWriteExt as _};

/// Push formatted argument to the formatter
#[macro_export]
macro_rules! argf {
    ($sf:expr, $($arg:tt)*) => {
        $sf.push_arg(format!($($arg)*).as_bytes()).await?
    };
}

/// Push argument to the formatter
#[macro_export]
macro_rules! arg {
    ($sf:expr, $arg:expr) => {
        $sf.push_arg($arg.as_bytes()).await?
    };
}

/// Push raw bytes to the formatter
#[macro_export]
macro_rules! raw {
    ($sf:expr, $arg:expr) => {
        $sf.push_raw($arg.as_bytes()).await?
    };
}

/// Finish formatting with a return value
#[macro_export]
macro_rules! finish {
    ($sf:expr, $retval:expr) => {
        $sf.finish($retval, None).await?
    };
    ($sf:expr, $retval:expr, $extra:expr) => {
        $sf.finish($retval, Some($extra)).await?
    };
}

/// Create a section with indented content
#[macro_export]
macro_rules! with_struct {
    ($sf:expr, $($body:tt)*) => {
        $sf.push_depth(b"{").await?;
        $($body)*
        $sf.pop_depth(b"}").await?;
    };
}

#[macro_export]
macro_rules! with_array {
    ($sf:expr, $($body:tt)*) => {
        $sf.push_depth(b"[").await?;
        $($body)*
        $sf.pop_depth(b"]").await?;
    };
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum FormattingStyle {
    #[default]
    OneLine,
    MultiLine,
}

pub struct Formatter<'f> {
    style: FormattingStyle,
    output: Pin<&'f mut dyn AsyncWrite>,
}

impl<'f> Formatter<'f> {
    pub fn new(output: Pin<&'f mut dyn AsyncWrite>, style: FormattingStyle) -> Self {
        Formatter { style, output }
    }

    pub async fn push_syscall(mut self, pid: u32, syscall_nr: i64) -> Result<SyscallFormatter<'f>> {
        let syscall_name = syscall_name_from_nr(syscall_nr)
            .ok_or_else(|| anyhow!(format!("Unknown syscall: {syscall_nr}")))?;

        let output = &mut self.output;

        output.write_all(pid.to_string().as_bytes()).await?;

        match self.style {
            FormattingStyle::OneLine => output.write_all(b" ").await?,
            FormattingStyle::MultiLine => output.write_all(b"\n\t").await?,
        };

        output.write_all(syscall_name.as_bytes()).await?;
        output.write_all(b"(").await?;

        Ok(SyscallFormatter {
            formatter: self,
            args: vec![0],
            syscall_nr,
        })
    }
}

pub struct SyscallFormatter<'f> {
    formatter: Formatter<'f>,
    args: Vec<usize>,
    syscall_nr: i64,
}

const INDENT_STEP: &[u8] = &[b' '; 4];
impl<'f> SyscallFormatter<'f> {
    fn argc(&self) -> usize {
        // We should always have at least one item.
        *self.args.last().unwrap()
    }

    fn inc_argc(&mut self) {
        // We should always have at least one item.
        *self.args.last_mut().unwrap() += 1;
    }

    pub async fn push_depth(&mut self, bracket: &[u8]) -> Result<()> {
        let output = &mut self.formatter.output;

        match self.formatter.style {
            FormattingStyle::OneLine => {
                output.write_all(b" ").await?;
                output.write_all(bracket).await?;
                output.write_all(b" ").await?;
            }
            FormattingStyle::MultiLine => {
                output.write_all(b" ").await?;
                output.write_all(bracket).await?;
            }
        }

        self.args.push(0);

        Ok(())
    }

    pub async fn pop_depth(&mut self, bracket: &[u8]) -> Result<()> {
        assert_ne!(self.get_depth(), 1);

        self.args.pop();

        let depth = self.get_depth();
        let output = &mut self.formatter.output;
        match self.formatter.style {
            FormattingStyle::OneLine => output.write_all(b" ").await?,
            FormattingStyle::MultiLine => {
                output.write_all(b"\n\t").await?;
                for _ in 0..depth {
                    output.write_all(INDENT_STEP).await?;
                }
            }
        }

        output.write_all(bracket).await?;

        Ok(())
    }

    pub fn get_depth(&self) -> usize {
        self.args.len()
    }

    pub async fn push_arg(&mut self, arg: &[u8]) -> Result<()> {
        let argc = self.argc();
        let depth = self.get_depth();

        let output = &mut self.formatter.output;

        // Always add a comma after a previous argument, if any.
        if argc > 0 {
            output.write_all(b",").await?;
        }
        match self.formatter.style {
            FormattingStyle::OneLine => {
                if argc > 0 {
                    output.write_all(b" ").await?;
                }
                output.write_all(arg).await?;
            }
            FormattingStyle::MultiLine => {
                output.write_all(b"\n\t").await?;
                for _ in 0..depth {
                    output.write_all(INDENT_STEP).await?;
                }
                output.write_all(arg).await?;
            }
        }

        self.inc_argc();

        Ok(())
    }

    pub async fn push_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let output = &mut self.formatter.output;
        output.write_all(bytes).await?;
        Ok(())
    }

    pub async fn finish(
        mut self,
        return_value: i64,
        suffix: Option<&[u8]>,
    ) -> Result<Formatter<'f>> {
        assert_eq!(self.get_depth(), 1);

        let formatted = crate::format_helpers::format_return_value(self.syscall_nr, return_value);

        let output = &mut self.formatter.output;

        if let FormattingStyle::MultiLine = self.formatter.style {
            output.write_all(b"\n\t").await?;
        }

        output.write_all(b") = ").await?;
        output.write_all(formatted.as_bytes()).await?;

        if let Some(suffix) = suffix {
            output.write_all(suffix).await?;
        }

        output.write_all(b"\n").await?;

        Ok(self.formatter)
    }
}

#[cfg(test)]
mod test {
    use indoc::indoc;
    use pinchy_common::syscalls::SYS_close;

    use super::*;

    #[tokio::test]
    async fn simple() {
        let mut output: Vec<u8> = vec![];
        let pinned_output = Pin::new(&mut output);

        let formatter = Formatter::new(pinned_output, FormattingStyle::MultiLine);

        let mut sysformatter = formatter.push_syscall(1, SYS_close).await.unwrap();
        sysformatter.push_arg(b"fd: 1").await.unwrap();

        let _ = sysformatter.finish(0, Some(b" <STUB>")).await.unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            indoc! {"
                1
                \tclose(
                \t    fd: 1
                \t) = 0 (success) <STUB>
            "}
            .to_string()
        );
    }

    #[tokio::test]
    async fn depth() {
        let mut output: Vec<u8> = vec![];
        let pinned_output = Pin::new(&mut output);

        let formatter = Formatter::new(pinned_output, FormattingStyle::MultiLine);

        let mut sf = formatter.push_syscall(1, SYS_close).await.unwrap();
        sf.push_arg(b"fd: 1").await.unwrap();

        sf.push_arg(b"timeout:").await.unwrap();

        sf.push_depth(b"{").await;

        sf.push_arg(b"seconds: 2").await.unwrap();
        sf.push_arg(b"nanos: 200").await.unwrap();

        sf.pop_depth(b"}").await;

        let _ = sf.finish(0, None).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output),
            indoc! {"
                1
                \tclose(
                \t    fd: 1,
                \t    timeout: {
                \t        seconds: 2,
                \t        nanos: 200
                \t    }
                \t) = 0 (success)
            "}
        );
    }
}
