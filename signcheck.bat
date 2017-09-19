FOR /L %%A IN (1,1,10000) DO (
	signtool verify /v /a %%A.exe
)
