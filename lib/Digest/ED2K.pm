package Digest::ED2K;
use base qw(Digest::base);
use common::sense;
use Digest::MD4;
use Exporter 'import';
our @EXPORT_OK = qw(ed2k ed2k_hex ed2k_base64);
use version 0.77; our $VERSION = version->declare('v1.0');

use constant CHUNK_SIZE => 9728000;

sub new {
	my $class = shift;
	bless {
		ctx => Digest::MD4->new,
		blocks => 0,
		buffer => '',
		_digest => undef,
	}, ref($class) || $class;
}

sub clone {
	my $self = shift;
	bless {
		ctx => $self->{ctx}->clone,
		blocks => $self->{blocks},
		buffer => $self->{buffer},
		_digest => $self->{_digest},
	}, ref($self);
}

sub add {
	my $self = shift;
	if(defined $self->{_digest}) {
		require Carp;
		Carp::croak("Can't add to a ed2k digest after it's been finalized. Please reset the object if you wish to reuse it.");
	}
	$self->{buffer} .= join '', @_;
	while(length($self->{buffer}) >= CHUNK_SIZE) {
		$self->{ctx}->add(Digest::MD4->new->add(substr($self->{buffer}, 0, CHUNK_SIZE))->digest);
		$self->{buffer} = substr($self->{buffer}, CHUNK_SIZE);
		$self->{blocks}++;
	}
	$self;
}

sub digest {
	my $self = shift;
	return $self->{_digest} if defined $self->{_digest};
	if(!$self->{blocks}) {
		$self->{_digest} = Digest::MD4->new->add($self->{buffer})->digest;
	}
	else {
		$self->{ctx}->add(Digest::MD4->new->add($self->{buffer})->digest);
		$self->{buffer} = '';
		$self->{_digest} = $self->{ctx}->digest;
	}
	return $self->{_digest};
}

sub ed2k($) {
	Digest::ED2K->new->add(@_)->digest;
}

sub ed2k_hex($) {
	Digest::ED2K->new->add(@_)->hexdigest;
}

sub ed2k_base64($) {
	Digest::ED2K->new->add(@_)->b64digest;
}

1;
__END__

=head1 NAME

Digest::ED2K - Perl implementation of the ED2k hash used in ED2K URIs

=head1 SYNOPSIS

 # Functional style
 use Digest::ED2K qw(ed2k ed2k_hex ed2k_base64);

 $hash = ed2k $data;
 $hash = ed2k_hex $data;
 $hash = ed2k_base64 $data;


 # OO style
 use Digest::ED2K;

 $ctx = Digest::ED2K->new;

 $ctx->add($data);
 $ctx->addfile(*FILE);

 $digest = $ctx->digest;
 $digest = $ctx->hexdigest;
 $digest = $ctx->b64digest;

=head1 DESCRIPTION

This module allows you to use the ED2K hash algorithm from within Perl programs.
It has the same interface as L<Digest>.

=head1 SEE ALSO

L<Exporter::Tiny> for additional import options.

=head1 AUTHORS

Benjamin Herweyer <benjamin.herweyer@gmail.com>

=head1 LICENSE

Copyright (c) 2010, Kulag <g.kulag@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=head1 REPOSITORY

http://github.com/Kulag/Digest-ED2K

=cut