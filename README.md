[![Build Status](https://travis-ci.org/powerman/perl-IO-Stream-Crypt-RC4.svg?branch=master)](https://travis-ci.org/powerman/perl-IO-Stream-Crypt-RC4)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-IO-Stream-Crypt-RC4/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-IO-Stream-Crypt-RC4?branch=master)

# NAME

IO::Stream::Crypt::RC4 - Crypt::RC4 plugin for IO::Stream

# VERSION

This document describes IO::Stream::Crypt::RC4 version v2.0.0

# SYNOPSIS

    use IO::Stream;
    use IO::Stream::Crypt::RC4;

    IO::Stream->new({
        ...
        plugin => [
            ...
            rc4     => IO::Stream::Crypt::RC4->new($passphrase),
            ...
        ],
    });

# DESCRIPTION

This module is plugin for [IO::Stream](https://metacpan.org/pod/IO::Stream) which allow you to encrypt all
data read/written by this stream using RC4.

# INTERFACE 

## new

    $plugin = IO::Stream::Crypt::RC4->new( $passphrase );

Create and return new IO::Stream plugin object.

# DIAGNOSTICS

- `usage: IO::Stream::Crypt::RC4->new("passphrase")`

    You probably called new() without $passphrase parameter.

# SUPPORT

## Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at [https://github.com/powerman/perl-IO-Stream-Crypt-RC4/issues](https://github.com/powerman/perl-IO-Stream-Crypt-RC4/issues).
You will be notified automatically of any progress on your issue.

## Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

[https://github.com/powerman/perl-IO-Stream-Crypt-RC4](https://github.com/powerman/perl-IO-Stream-Crypt-RC4)

    git clone https://github.com/powerman/perl-IO-Stream-Crypt-RC4.git

## Resources

- MetaCPAN Search

    [https://metacpan.org/search?q=IO-Stream-Crypt-RC4](https://metacpan.org/search?q=IO-Stream-Crypt-RC4)

- CPAN Ratings

    [http://cpanratings.perl.org/dist/IO-Stream-Crypt-RC4](http://cpanratings.perl.org/dist/IO-Stream-Crypt-RC4)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/IO-Stream-Crypt-RC4](http://annocpan.org/dist/IO-Stream-Crypt-RC4)

- CPAN Testers Matrix

    [http://matrix.cpantesters.org/?dist=IO-Stream-Crypt-RC4](http://matrix.cpantesters.org/?dist=IO-Stream-Crypt-RC4)

- CPANTS: A CPAN Testing Service (Kwalitee)

    [http://cpants.cpanauthors.org/dist/IO-Stream-Crypt-RC4](http://cpants.cpanauthors.org/dist/IO-Stream-Crypt-RC4)

# AUTHOR

Alex Efros &lt;powerman@cpan.org>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2008- by Alex Efros &lt;powerman@cpan.org>.

This is free software, licensed under:

    The MIT (X11) License
