void CWE476bad()
{
    {
        int *Pointer ;
        if ((Pointer != NULL) & (*Pointer == 5))
        {
            printLine("intOne == 5");
        }
    }
}