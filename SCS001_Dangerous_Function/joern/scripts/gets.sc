importCpg("/Users/afiaasante/Security-Code-Smells/SCS001_Dangerous_Function/cpg.bin")
import java.io.PrintWriter

val writer = new PrintWriter("results/joern_scs001_results3.txt")

// Run the query
cpg.call.name("gets")
  .location
  .map(l => s"${l.filename}:${l.lineNumber.get}:SCS001:Dangerous_Function_Use:gets")
  .foreach(writer.println)

writer.close()