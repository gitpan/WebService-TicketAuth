
package Example::TicketAuth;

@Example::TicketAuth::ISA = qw(WebService::TicketAuth);

use strict;
use WebService::TicketAuth;

use vars qw($VERSION %FIELDS);
our $VERSION = '1.00';

sub new {
    my ($this) = @_;
    my $class = ref($this) || $this;
    my $self = $class->SUPER::new(@_);

    return $self;
}

# Override how long to allow ticket
sub ticket_duration {
    my $self = shift;
    my $username = shift;
    if ($username eq 'admin') {
        # Give admins 15 min login access
        return 15*60;
    } else {
        # Give everyone else 24 hour login
        return 24*60*60;
    }
}

# Override for determining if user is valid
sub is_valid {
    my $self = shift;
    my ($username, $password) = @_;

    if ($username eq 'admin' && $password eq 'admin') {
        return 1;
    } elsif ($username eq 'demo' && $password eq 'demo') {
        return 1;
    } else {
        return undef;
    }
}

1;
