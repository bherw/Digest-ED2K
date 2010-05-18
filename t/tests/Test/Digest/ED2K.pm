# Copyright (c) 2010, Kulag <g.kulag@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
package Test::Digest::ED2K;
use common::sense;
use Test::Class;
use Test::Most;
use base 'Test::Class';
use constant CHUNK_SIZE => 9728000;

sub class { 'Digest::ED2K' }

sub _startup : Tests(startup => 3) {
	my $test = shift;
	require_ok $test->class;
	can_ok $test->class, 'import';
	lives_ok { $test->class->import(qw(ed2k ed2k_hex ed2k_base64)) } 'Importing the helpers works';
}

sub constructor : Tests(3) {
	my $test = shift;
	my $class = $test->class;
	can_ok $class, 'new';
	ok my $instance = $class->new, 'Instance creation works';
	isa_ok $instance, $class, "Is a $class object";
}

sub clone : Tests(2) {
	my $test = shift;
	my $class = $test->class;
	can_ok $class, 'clone';
	my $original = $class->new->add('abc123');
	my $copy = $original->clone;
	is $copy->hexdigest, $original->hexdigest, 'cloning works';
}

# Assumes hexdigest and and b64digest are ok since they're inherited from Digest::base.
sub digest : Tests(8) {
	my $test = shift;
	my $class = $test->class;
	can_ok $class, 'digest';
	can_ok $class, 'hexdigest';
	can_ok $class, 'b64digest';
	is $class->new->add('aaa')->hexdigest, '918d7099b77c7a06634c62ccaf5ebac7', 'Subchunk string is correct';

	# Test the tricky CHUNK_SIZE multiples.
	# http://wiki.anidb.net/w/Ed2k-hash#How_is_an_ed2k_hash_calculated_exactly.3F
	isnt $class->new->add("\x00" x CHUNK_SIZE)->hexdigest, 'd7def262a127cd79096a108e7a9fc138', 'The blue method is not in use for ==CHUNK_SIZE';
	is $class->new->add("\x00" x CHUNK_SIZE)->hexdigest, 'fc21d9af828f92a8df64beac3357425d', 'The red method is in use for ==CHUNK_SIZE';
	isnt $class->new->add("\x00" x (CHUNK_SIZE * 2))->hexdigest, '194ee9e4fa79b2ee9f8829284c466051', 'The blue method is not in use for ==CHUNK_SIZE*2';
	is $class->new->add("\x00" x (CHUNK_SIZE * 2))->hexdigest, '114b21c63a74b6ca922291a11177dd5c', 'The red method is in use for ==CHUNK_SIZE*2';
}

sub helpers : Tests(3) {
	my $test = shift;
	my $class = $test->class;

	is ed2k('abc123'), $class->new->add('abc123')->digest, 'ed2k digest helper works';
	is ed2k_hex('abc123'), $class->new->add('abc123')->hexdigest, 'ed2k hexdigest helper works';
	is ed2k_base64('abc123'), $class->new->add('abc123')->b64digest, 'ed2k b64digest helper works';
}

1;