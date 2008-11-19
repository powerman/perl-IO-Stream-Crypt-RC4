package IO::Stream::Crypt::RC4;

use warnings;
use strict;
use Carp;

use version; our $VERSION = qv('1.0.1');    # update POD & Changes & README

# update DEPENDENCIES in POD & Makefile.PL & README
use IO::Stream::const;
use Crypt::RC4;


sub new {
    my ($class, $passphrase) = @_;
    croak 'usage: IO::Stream::Crypt::RC4->new("passphrase")'
        if !defined $passphrase;
    my $self = bless {
        out_buf     => q{},                 # modified on: OUT
        out_pos     => undef,               # modified on: OUT
        out_bytes   => 0,                   # modified on: OUT
        in_buf      => q{},                 # modified on: IN
        in_bytes    => 0,                   # modified on: IN
        ip          => undef,               # modified on: RESOLVED
        is_eof      => undef,               # modified on: EOF
        _rcrypt     => Crypt::RC4->new($passphrase),
        _wcrypt     => Crypt::RC4->new($passphrase),
        }, $class;
    return $self;
}

sub PREPARE {
    my ($self, $fh, $host, $port) = @_;
    $self->{_slave}->PREPARE($fh, $host, $port);
    return;
}

sub WRITE {
    my ($self) = @_;
    my $m = $self->{_master};
    my $s = substr $m->{out_buf}, $m->{out_pos}||0;
    my $n = length $s;
    $self->{out_buf} .= $self->{_wcrypt}->RC4($s);
    if (defined $m->{out_pos}) {
        $m->{out_pos} += $n;
    } else {
        $m->{out_buf} = q{};
    }
    $m->{out_bytes} += $n;
    $m->EVENT(OUT);
    $self->{_slave}->WRITE();
    return;
}

sub EVENT {
    my ($self, $e, $err) = @_;
    my $m = $self->{_master};
    if ($e & OUT) {
        $e &= ~OUT;
        return if !$e && !$err;
    }
    if ($e & IN) {
        $m->{in_buf}    .= $self->{_rcrypt}->RC4($self->{in_buf});
        $m->{in_bytes}  += $self->{in_bytes};
        $self->{in_buf}  = q{};
        $self->{in_bytes}= 0;
    }
    if ($e & RESOLVED) {
        $m->{ip} = $self->{ip};
    }
    if ($e & EOF) {
        $m->{is_eof} = $self->{is_eof};
    }
    $m->EVENT($e, $err);
    return;
}


1; # Magic true value required at end of module
__END__

=head1 NAME

IO::Stream::Crypt::RC4 - Crypt::RC4 plugin for IO::Stream


=head1 VERSION

This document describes IO::Stream::Crypt::RC4 version 1.0.1


=head1 SYNOPSIS

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

=head1 DESCRIPTION

This module is plugin for L<IO::Stream> which allow you to encrypt all
data read/written by this stream using RC4.


=head1 INTERFACE 

=over

=item new($passphrase)

Create and return new IO::Stream plugin object.

=back


=head1 DIAGNOSTICS

=over

=item C<< usage: IO::Stream::Crypt::RC4->new("passphrase") >>

You probably called new() without $passphrase parameter.

=back


=head1 CONFIGURATION AND ENVIRONMENT

IO::Stream::Crypt::RC4 requires no configuration files or environment variables.


=head1 DEPENDENCIES

L<IO::Stream>,
L<Crypt::RC4>.


=head1 INCOMPATIBILITIES

None reported.


=head1 BUGS AND LIMITATIONS

No bugs have been reported.

Please report any bugs or feature requests to author, or
C<bug-ev-stream-crypt-rc4@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Alex Efros  C<< <powerman-asdf@ya.ru> >>


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2008, Alex Efros C<< <powerman-asdf@ya.ru> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
