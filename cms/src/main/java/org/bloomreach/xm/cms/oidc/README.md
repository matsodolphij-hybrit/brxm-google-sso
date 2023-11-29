**Important**
This package structure has to be maintained. It can't be altered to a kvk package structure without breaking Spring security.

Spring boot has been added to the project in BRXM 14+. An application context is started automatically with an auto scan on this (org.bloomreach.xm.cms) package structure. The below link describes how to work with this application context.

https://xmdocumentation.bloomreach.com/library/upgrade-minor-versions/upgrade-14.5-to-14.6.html

FYI: adding a new spring application context will result in compile errors.