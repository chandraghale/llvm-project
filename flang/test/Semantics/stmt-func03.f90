! RUN: %flang_fc1 -fsyntax-only -pedantic %s 2>&1 | FileCheck %s
! CHECK-NOT: error:
! CHECK-NOT: Internal:
program main
  integer :: passed, failed
  passed = 0
  failed = 0
  call internal_sub()
  call exit(failed)
contains
  subroutine internal_sub()
    integer :: i, result
    ! Host-associated sibling internal function name should be shadowed
    ! by this statement function definition.
    stmt_function(i) = i * 2
    i = 1
    result = stmt_function(i)
    if (result .eq. 2) then
      passed = passed + 1
    else
      failed = failed + 1
    end if
  end subroutine internal_sub
  integer function stmt_function(arg)
    integer :: arg
    stmt_function = arg * 3
  end function stmt_function
end program main
