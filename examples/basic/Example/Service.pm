
package Example::Service;
@Example::Service::ISA = qw(Example::TicketAuth);

use strict;
use Example::TicketAuth;

use vars qw($VERSION %FIELDS);
our $VERSION = '1.00';

sub new {
    my ($this) = @_;
    my $class = ref($this) || $this;
    my $self = $class->SUPER::new(@_);

    return $self;
}


sub public {
    my $self = shift;

    return 'This is a public routine';
}


sub protected {
    my $self = shift;
    my $header = pop;

    my $username = $self->get_username($header);

    return "This is a protected routine, but '$username' is authorized to use it.\n";
}

1;
