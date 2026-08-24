Bug Fixes
---------

- Block template creation now checks credit pool limits across complete
  transaction packages. Because Asset Unlock limits are cumulative, a package
  may exceed the block's limit even though its transactions were accepted
  individually. Such packages are now skipped so miners can continue building
  a template instead of template creation failing. (#7570)
