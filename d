
# # app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:deployment1234@154.53.42.12/deployment')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:1234Abcd@154.53.42.12/deployment')
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False







# #edit files
# @app.route('/edit_file/<int:file_id>', methods=['GET', 'POST'])
# def edit_file(file_id):
#     file_to_edit = job_desc_files.query.get(file_id)

#     if not file_to_edit:
#         flash('File not found.', 'danger')
#         return redirect(url_for('admin_panel'))

#     if request.method == 'POST':
#         # Get updated values from the form
#         new_filename = request.form.get('filename')
#         new_file_type_name = request.form.get('file_type_name')
#         new_file_description = request.form.get('file_description')

#         # Update file information
#         file_to_edit.filename = new_filename
#         file_to_edit.file_type_name = new_file_type_name
#         file_to_edit.file_description = new_file_description
#         db.session.commit()

#         flash('File updated successfully!', 'success')
#         return redirect(url_for('admin_panel'))

#     return render_template('admin_panel', file=file_to_edit)