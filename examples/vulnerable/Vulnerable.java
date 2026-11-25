import javax.servlet.http.*;

/** Один из классических примеров SQL-инъекции из OWASP Benchmark. */
public class Vulnerable extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String id = request.getParameter("id");
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
